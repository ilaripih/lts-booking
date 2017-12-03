package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username" bson:"username"`
	Name string `json:"name" bson:"name"`
	Email string `json:"email" bson:"email"`
	StreetAddress string `json:"street_address" bson:"street_address"`
	PostalCode string `json:"postal_code" bson:"postal_code"`
	PhoneNumber string `json:"phone_number" bson:"phone_number"`
	LtsMember bool `json:"lts_member" bson:"lts_member"`
	Level string `json:"level" bson:"level"`
	Password string `bson:"password" json:"-"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type Court struct {
	Id bson.ObjectId `json:"_id" bson:"_id"`
	Name string `json:"name" bson:"name"`
	BookingText string `json:"booking_text" bson:"booking_text"`
	MaxBookingLength int `json:"max_booking_length" bson:"max_booking_length"`
	WeekDaysOpen int `json:"week_days_open" bson:"week_days_open"`
	WeekDaysClose int `json:"week_days_close" bson:"week_days_close"`
	SaturdayOpen int `json:"saturday_open" bson:"saturday_open"`
	SaturdayClose int `json:"saturday_close" bson:"saturday_close"`
	SundayOpen int `json:"sunday_open" bson:"sunday_open"`
	SundayClose int `json:"sunday_close" bson:"sunday_close"`
	CreatedAt time.Time `bson:"created_at" json:"-"`
}

type Booking struct {
	Id bson.ObjectId `json:"_id" bson:"_id"`
	UserName string `json:"username" bson:"username"`
	Title string `json:"title" bson:"title"`
	CourtId bson.ObjectId `json:"court_id" bson:"court_id"`
	Begin time.Time `json:"begin" bson:"begin"`
	End time.Time `json:"end" bson:"end"`
	CreatedAt time.Time `bson:"created_at" json:"-"`
	PaidAt *time.Time `bson:"paid_at" json:"paid_at"`
	PaymentType string `bson:"payment_type" json:"payment_type"`
}

var mongo *mgo.Session
var appDir = "./app"
var store = sessions.NewCookieStore([]byte("lts-cookie-store"))
var loc, _ = time.LoadLocation("Europe/Helsinki")

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getUser(username string) (*User, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	var user User
	err := c.Find(bson.M{"username": username}).One(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func saveSession(w http.ResponseWriter, r *http.Request, user *User) error {
    sess, err := store.Get(r, "user")
    if err != nil {
    	log.Println("Could not save user session")
        return err
    }

    sess.Values["username"] = user.Username
    sess.Values["name"] = user.Name
    sess.Values["email"] = user.Email
    sess.Values["street_address"] = user.StreetAddress
    sess.Values["postal_code"] = user.PostalCode
    sess.Values["phone_number"] = user.PhoneNumber
    sess.Values["lts_member"] = user.LtsMember
    sess.Values["level"] = user.Level
    sess.Save(r, w)

    return nil
}

func myHandler(fn func(http.ResponseWriter, *http.Request, map[string]interface{}, *sessions.Session) (int, error), auth string, required ...string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := store.Get(r, "user")
		if err != nil {
			log.Println(r.URL, r.RemoteAddr, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if auth != "" {
			if _, ok := sess.Values["username"]; !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if auth == "admin" && sess.Values["level"] != "admin" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		defer r.Body.Close()

		var m map[string]interface{}
		if err := decoder.Decode(&m); err != nil {
			log.Println(r.URL, r.RemoteAddr, "JSON decoding error:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if m == nil {
			m = make(map[string]interface{})
		}

		for _, param := range required {
			if _, ok := m[param]; !ok {
				formVal := r.FormValue(param)
				if formVal != "" {
					m[param] = formVal
				} else {
					log.Println(r.URL, r.RemoteAddr, "missing_parameter:", param)
					http.Error(w, "missing_parameter", http.StatusBadRequest)
					return
				}
			}
		}

		defer func() {
			if err, ok := recover().(error); ok {
				log.Println(r.URL, r.RemoteAddr, "Recovered panic:", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}()
		status, err := fn(w, r, m, sess)
		if err != nil {
			log.Println(r.URL, r.RemoteAddr, err)
			http.Error(w, err.Error(), status)
			return
		}
	})
}

func signupHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	username := m["username"].(string)
	password := m["password"].(string)

	if len(username) < 4 {
		return http.StatusBadRequest, errors.New("invalid_username")
	}
	if len(password) < 8 {
		return http.StatusBadRequest, errors.New("short_password")
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")
	count, err := c.Find(bson.M{"username": username}).Count()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if count > 0 {
		return http.StatusBadRequest, errors.New("user_already_exists")
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	now := time.Now()
	var user User
	user.Username = username
	user.Password = hashedPassword
	user.CreatedAt = now
	user.Level = "user"
	err = c.Insert(&user)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	saveSession(w, r, &user)
	w.Header().Set("Content-Type", "application/json")

	encoder := json.NewEncoder(w)
	err = encoder.Encode(&user)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	username := m["username"].(string)
	password := m["password"].(string)

	user, err := getUser(username)
	if err != nil || !checkPasswordHash(password, user.Password) {
		return http.StatusUnauthorized, errors.New("invalid_credentials")
	}

	saveSession(w, r, user)
	w.Header().Set("Content-Type", "application/json")

	encoder := json.NewEncoder(w)
	err = encoder.Encode(user)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sess, err := store.Get(r, "user")
	if err != nil {
		log.Println("Could not get user session:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sess.Values = make(map[interface{}]interface{})
	sess.Options.MaxAge = -1
	sess.Save(r, w)
}

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user")
	if err != nil {
		log.Println("Could not get user session:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)

	m := make(map[string]interface{})
	if _, ok := session.Values["username"]; ok {
		for key, value := range session.Values {
			m[key.(string)] = value
		}
	}

	err = encoder.Encode(m)
	if err != nil {
		log.Println("Could not encode JSON:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func updateUserHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	name := m["name"].(string)
	email := m["email"].(string)
	streetAddress := m["street_address"].(string)
	postalCode := m["postal_code"].(string)
	phoneNumber := m["phone_number"].(string)

	sess.Values["name"] = name
	sess.Values["email"] = email
	sess.Values["street_address"] = streetAddress
	sess.Values["postal_code"] = postalCode
	sess.Values["phone_number"] = phoneNumber
	sess.Save(r, w)

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	if err := c.Update(bson.M{"username": sess.Values["username"]}, bson.M{"$set": bson.M{
		"name": name,
		"email": email,
		"street_address": streetAddress,
		"postal_code": postalCode,
		"phone_number": phoneNumber,
	}}); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func updateUserPasswordHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	currentPassword := m["current_password"].(string)
	newPassword := m["new_password"].(string)

	if len(newPassword) < 8 {
		return http.StatusBadRequest, errors.New("short_password")
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	var user bson.M
	if err := c.Find(bson.M{"username": sess.Values["username"]}).One(&user); err != nil {
		return http.StatusInternalServerError, err
	}
	if !checkPasswordHash(currentPassword, user["password"].(string)) {
		return http.StatusUnauthorized, errors.New("invalid_current_password")
	}

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if err := c.Update(bson.M{"username": sess.Values["username"]}, bson.M{
		"$set": bson.M{"password": hashedPassword},
	}); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func courtsHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("courts")

	var courts []Court
	if err := c.Find(bson.M{}).All(&courts); err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(courts); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func courtHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	idStr := m["_id"].(string)
	if !bson.IsObjectIdHex(idStr) {
		return http.StatusNotFound, errors.New("not_found")
	}
	id := bson.ObjectIdHex(idStr)

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("courts")

	var court Court
	if err := c.Find(bson.M{"_id": id}).One(&court); err != nil {
		return http.StatusNotFound, errors.New("not_found")
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&court); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func saveCourtHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("courts")

	idStr := m["_id"].(string)
	var id bson.ObjectId
	data := bson.M{
		"name": m["name"].(string),
		"booking_text": m["booking_text"].(string),
		"max_booking_length": int(m["max_booking_length"].(float64)),
		"week_days_open": int(m["week_days_open"].(float64)),
		"week_days_close": int(m["week_days_close"].(float64)),
		"saturday_open": int(m["saturday_open"].(float64)),
		"saturday_close": int(m["saturday_close"].(float64)),
		"sunday_open": int(m["sunday_open"].(float64)),
		"sunday_close": int(m["sunday_close"].(float64)),
	}

	if idStr == "new" {
		id = bson.NewObjectId()
		data["_id"] = id
		now := time.Now()
		data["created_at"] = &now
		if err := c.Insert(data); err != nil {
			return http.StatusInternalServerError, errors.New("already_exists")
		}
	} else {
		if !bson.IsObjectIdHex(idStr) {
			return http.StatusNotFound, errors.New("not_found")
		}

		id = bson.ObjectIdHex(idStr)
		if err := c.Update(bson.M{"_id": id}, bson.M{"$set": data}); err != nil {
			return http.StatusNotFound, errors.New("not_found")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(bson.M{"_id": id}); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func deleteCourtHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	idStr := m["_id"].(string)
	if !bson.IsObjectIdHex(idStr) {
		return http.StatusNotFound, errors.New("not_found")
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("courts")

	id := bson.ObjectIdHex(idStr)
	if err := c.RemoveId(id); err != nil {
		return http.StatusBadRequest, err
	}

	return http.StatusOK, nil
}

func bookingHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	idStr := m["_id"].(string)
	if !bson.IsObjectIdHex(idStr) {
		return http.StatusNotFound, errors.New("not_found")
	}

	find := bson.M{
		"_id": bson.ObjectIdHex(idStr),
	}
	if sess.Values["level"] != "admin" {
		find["username"] = sess.Values["username"]
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("bookings")

	var booking bson.M
	if err := c.Find(find).One(&booking); err != nil {
		return http.StatusNotFound, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(booking); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func bookingsHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	beginStr := m["date_begin"].(string)
	endStr := m["date_end"].(string)
	const shortForm = "2006-01-02 15:04:05"
	begin, err := time.ParseInLocation(shortForm, beginStr + " 00:00:00", loc)
	if err != nil {
		return http.StatusBadRequest, err
	}
	end, err := time.ParseInLocation(shortForm, endStr + " 23:59:59", loc)
	if err != nil {
		return http.StatusBadRequest, err
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("bookings")

	find := bson.M{
		"begin": bson.M{"$gte": begin},
		"end": bson.M{"$lte": end},
	}
	fields := bson.M{
		"_id": 1,
		"court_id": 1,
		"begin": 1,
		"end": 1,
		"title": 1,
	}
	if val, ok := m["court_id"]; ok {
		idStr := val.(string)
		if !bson.IsObjectIdHex(idStr) {
			return http.StatusNotFound, errors.New("not_found")
		}
		find["court_id"] = bson.ObjectIdHex(idStr)
	}
	if sess.Values["level"] == "admin" {
		fields["username"] = 1
		fields["created_at"] = 1
		fields["paid_at"] = 1
		fields["payment_type"] = 1
		if val, ok := m["username"]; ok {
			idStr := val.(string)
			find["username"] = idStr
		}
	} else if _, ok := m["username"]; ok {
		return http.StatusUnauthorized, errors.New("unauthorized")
	}
	if val, ok := m["my_bookings"]; ok {
		filterMyBookings := val.(bool)
		if filterMyBookings {
			find["username"] = sess.Values["username"]
		}
	}

	sortDir := ""
	if val, ok := m["sort_desc"]; ok {
		sortDesc := val.(bool)
		if sortDesc {
			sortDir = "-"
		}
	}

	var bookings []bson.M
	if err := c.Find(find).Sort(sortDir + "begin").Select(fields).All(&bookings); err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(bookings); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func generateTimestamp(date string, t int) (time.Time, error) {
	hours := t / 60
	minutes := t - (hours * 60)

	zeroPad := func(i int) string {
		s := strconv.Itoa(i)
		if len(s) > 1 {
			return s
		}
		return "0" + s
	}
	tsStr := date + " " + zeroPad(hours) + ":" + zeroPad(minutes) + ":00"

	const shortForm = "2006-01-02 15:04:05"
	ts, err := time.ParseInLocation(shortForm, tsStr, loc)
	if err != nil {
		return time.Time{}, err
	}
	return ts, nil
}

func hasFullUserDetails(sess *sessions.Session) bool {
	required := []string{
		"username",
		"name",
		"email",
		"street_address",
		"postal_code",
		"phone_number",
	}
	for _, field := range required {
		val, ok := sess.Values[field]
		if !ok || val == "" {
			return false
		}
	}

	return true
}

var bookHandlerMutex sync.Mutex
func bookHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	if !hasFullUserDetails(sess) {
		return http.StatusUnauthorized, errors.New("missing_user_details")
	}

	courtIdStr := m["court_id"].(string)
	dateStr := m["date"].(string)
	beginNum := int(m["time_begin"].(float64))
	endNum := int(m["time_end"].(float64))

	if !bson.IsObjectIdHex(courtIdStr) {
		return http.StatusNotFound, errors.New("not_found")
	}
	courtId := bson.ObjectIdHex(courtIdStr)

	begin, err := generateTimestamp(dateStr, beginNum)
	if err != nil {
		return http.StatusBadRequest, err
	}
	end, err := generateTimestamp(dateStr, endNum)
	if err != nil {
		return http.StatusBadRequest, err
	}

	now := time.Now()

	if begin.After(end) || now.After(begin) {
		return http.StatusBadRequest, errors.New("court_unavailable")
	}

	weekDay := begin.Weekday()
	dayPrefix := "week_days"
	if weekDay == time.Saturday {
		dayPrefix = "saturday"
	} else if weekDay == time.Sunday {
		dayPrefix = "sunday"
	}
	fieldOpen := dayPrefix + "_open"
	fieldClose := dayPrefix + "_close"

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("courts")

	// Checking that the court is free and inserting the booking needs to be
	// one atomic operation.
	bookHandlerMutex.Lock()
	defer bookHandlerMutex.Unlock()

	var court Court
	if err := c.Find(bson.M{
		"_id": courtId,
		fieldOpen: bson.M{"$lte": beginNum},
		fieldClose: bson.M{"$gte": endNum},
	}).One(&court); err != nil {
		return http.StatusBadRequest, errors.New("court_unavailable")
	}

	isAdmin := (sess.Values["level"] == "admin")
	if !isAdmin && court.MaxBookingLength * 60 < (endNum - beginNum) {
		return http.StatusBadRequest, errors.New("max_booking_length_exceeded")
	}

	c = s.DB("").C("bookings")
	count, err := c.Find(bson.M{
		"court_id": courtId,
		"begin": bson.M{"$lt": end},
		"end": bson.M{"$gt": begin},
	}).Count()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if count > 0 {
		return http.StatusBadRequest, errors.New("court_already_booked")
	}

	title := sess.Values["name"]
	if isAdmin {
		if val, ok := m["title"]; ok {
			title = val.(string)
		}
	}

	booking := bson.M{
		"username": sess.Values["username"],
		"title": title,
		"court_id": courtId,
		"begin": begin,
		"end": end,
		"created_at": &now,
	}
	if err := c.Insert(booking); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func cancelBookingHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	idStr := m["_id"].(string)
	if !bson.IsObjectIdHex(idStr) {
		return http.StatusNotFound, errors.New("not_found")
	}
	id := bson.ObjectIdHex(idStr)

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("bookings")

	fields := bson.M{"_id": id}
	if sess.Values["level"] != "admin" {
		fields["username"] = sess.Values["username"]
		fields["begin"] = bson.M{"$gt": time.Now().Add(time.Hour * 8)}
	}

	if err := c.Remove(fields); err != nil {
		return http.StatusBadRequest, err
	}

	return http.StatusOK, nil
}

func setBookingPaymentHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	idStr := m["_id"].(string)
	if !bson.IsObjectIdHex(idStr) {
		return http.StatusNotFound, errors.New("not_found")
	}
	id := bson.ObjectIdHex(idStr)
	values := bson.M{"_id": id}

	paymentType := m["payment_type"]
	if paymentType == "not_paid" {
		paymentType = ""
		values["paid_at"] = nil
	} else {
		ts := time.Now()
		values["paid_at"] = &ts
	}
	values["payment_type"] = paymentType

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("bookings")

	if err := c.Update(bson.M{"_id": id}, bson.M{"$set": values}); err != nil {
		return http.StatusNotFound, err
	}

	return http.StatusOK, nil
}

func userHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	username := m["username"].(string)

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	var user User
	if err := c.Find(bson.M{"username": username}).One(&user); err != nil {
		return http.StatusNotFound, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func usersHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	var users []User
	if err := c.Find(nil).All(&users); err != nil {
		return http.StatusNotFound, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(users); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, appDir + "/index.html")
}

func addIndexes(s *mgo.Session) error {
	m := make(map[string][]mgo.Index)

	m["users"] = append(m["users"], mgo.Index{
		Key: []string{"username"},
		Unique: true,
	})
	m["courts"] = append(m["courts"], mgo.Index{
		Key: []string{"name"},
		Unique: true,
	})
	m["bookings"] = append(m["bookings"], mgo.Index{
		Key: []string{"begin"},
		Unique: false,
	})
	m["bookings"] = append(m["bookings"], mgo.Index{
		Key: []string{"end"},
		Unique: false,
	})

	for c, indexes := range m {
		for _, index := range indexes {
			if err := s.DB("").C(c).EnsureIndex(index); err != nil {
				return err
			}
		}
	}
	return nil
}

func redirect(w http.ResponseWriter, req *http.Request) {
    // remove/add not default ports from req.Host
    target := "https://" + req.Host + req.URL.Path
    if len(req.URL.RawQuery) > 0 {
        target += "?" + req.URL.RawQuery
    }
    http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

func main() {
	var err error
	mongo, err = mgo.Dial("localhost/lts-booking")
	if err != nil {
		log.Panic("Unable to establish MongoDB connection:", err)
	}
	defer mongo.Close()
	mongo.SetMode(mgo.Monotonic, true)
	log.Println("Connected to MongoDB at localhost")

	if err := addIndexes(mongo); err != nil {
		log.Panic("Unable to add MongoDB index:", err)
	}

	certManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("ltsvaraus.com"),
		Cache: autocert.DirCache("certs"),
	}

	fs := http.FileServer(http.Dir(appDir))
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/app/", http.StripPrefix("/app/", fs).ServeHTTP)

	http.HandleFunc("/api/signup", myHandler(signupHandler, "", "username", "password"))
	http.HandleFunc("/api/login", myHandler(loginHandler, "", "username", "password"))
	http.HandleFunc("/api/logout", logoutHandler)
	http.HandleFunc("/api/session", sessionHandler)
	http.HandleFunc("/api/update_user_data", myHandler(updateUserHandler, "user",
		"name", "email", "street_address", "postal_code", "phone_number"))
	http.HandleFunc("/api/courts", myHandler(courtsHandler, ""))
	http.HandleFunc("/api/court", myHandler(courtHandler, "", "_id"))
	http.HandleFunc("/api/save_court", myHandler(saveCourtHandler, "admin",
		"_id", "name", "booking_text", "max_booking_length", "week_days_open", "week_days_close",
		"saturday_open", "saturday_close",
		"sunday_open", "sunday_close"))
	http.HandleFunc("/api/delete_court", myHandler(deleteCourtHandler, "admin", "_id"))
	http.HandleFunc("/api/booking", myHandler(bookingHandler, "user", "_id"))
	http.HandleFunc("/api/bookings", myHandler(bookingsHandler, "", "date_begin", "date_end"))
	http.HandleFunc("/api/book_court", myHandler(bookHandler, "user",
		"court_id", "date", "time_begin", "time_end"))
	http.HandleFunc("/api/cancel_booking", myHandler(cancelBookingHandler, "user", "_id"))
	http.HandleFunc("/api/set_booking_payment", myHandler(setBookingPaymentHandler, "admin",
		"_id", "payment_type"))
	http.HandleFunc("/api/update_user_password", myHandler(updateUserPasswordHandler, "user",
		"current_password", "new_password"))
	http.HandleFunc("/api/user", myHandler(userHandler, "admin", "username"))
	http.HandleFunc("/api/users", myHandler(usersHandler, "admin"))

	port := os.Getenv("LTS_BOOKING_PORT")
	if port != "" {
		log.Println("Listening at localhost:" + port)
		err = http.ListenAndServe(":" + port, context.ClearHandler(http.DefaultServeMux))
	} else {
		go http.ListenAndServe(":80", http.HandlerFunc(redirect))

		server := &http.Server{
			Addr: ":443",
			Handler: context.ClearHandler(http.DefaultServeMux),
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		log.Println("Listening at port 443")
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		log.Println(err)
	}
}
