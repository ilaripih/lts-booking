package main

import (
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type CustomField struct {
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
}

type User struct {
	Username      string        `json:"username" bson:"username"`
	Name          string        `json:"name" bson:"name"`
	Email         string        `json:"email" bson:"email"`
	StreetAddress string        `json:"street_address" bson:"street_address"`
	PostalCode    string        `json:"postal_code" bson:"postal_code"`
	PhoneNumber   string        `json:"phone_number" bson:"phone_number"`
	LtsMember     bool          `json:"lts_member" bson:"lts_member"`
	Level         string        `json:"level" bson:"level"`
	Password      string        `bson:"password" json:"-"`
	CreatedAt     time.Time     `bson:"created_at" json:"created_at"`
	Disabled      bool          `bson:"disabled" json:"disabled"`
	Custom        []CustomField `json:"custom" bson:"custom"`
}

type Court struct {
	Id                 bson.ObjectId   `json:"_id" bson:"_id"`
	Name               string          `json:"name" bson:"name"`
	BookingText        string          `json:"booking_text" bson:"booking_text"`
	MaxBookingLength   int             `json:"max_booking_length" bson:"max_booking_length"`
	MaxBookings        int             `json:"max_bookings" bson:"max_bookings"`
	CancellationPeriod int             `json:"cancellation_period" bson:"cancellation_period"`
	WeekDaysOpen       int             `json:"week_days_open" bson:"week_days_open"`
	WeekDaysClose      int             `json:"week_days_close" bson:"week_days_close"`
	SaturdayOpen       int             `json:"saturday_open" bson:"saturday_open"`
	SaturdayClose      int             `json:"saturday_close" bson:"saturday_close"`
	SundayOpen         int             `json:"sunday_open" bson:"sunday_open"`
	SundayClose        int             `json:"sunday_close" bson:"sunday_close"`
	CreatedAt          time.Time       `bson:"created_at" json:"-"`
	Group              string          `json:"group" bson:"group"`
	Targets            []bson.ObjectId `json:"targets" bson:"targets"`
	HourPrecision      bool            `json:"hour_precision" bson:"hour_precision"`
}

type Booking struct {
	Id          bson.ObjectId  `json:"_id" bson:"_id"`
	UserName    string         `json:"username" bson:"username"`
	Title       string         `json:"title" bson:"title"`
	CourtId     bson.ObjectId  `json:"court_id" bson:"court_id"`
	Begin       time.Time      `json:"begin" bson:"begin"`
	End         time.Time      `json:"end" bson:"end"`
	CreatedAt   time.Time      `bson:"created_at" json:"-"`
	PaidAt      *time.Time     `bson:"paid_at" json:"paid_at"`
	PaymentType string         `bson:"payment_type" json:"payment_type"`
	WeekDay     int            `bson:"weekday" json:"weekday"`
	Parent      *bson.ObjectId `json:"parent" bson:"parent"`
}

type UserDetailDependency struct {
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
}

type CustomUserDetail struct {
	Name       string                `json:"name" bson:"name"`
	Type       int                   `json:"type" bson:"type"`
	Options    []string              `json:"options" bson:"options"`
	Dependency *UserDetailDependency `json:"dependency" bson:"dependency"`
	Unique     bool                  `json:"unique" bson:"unique"`
}

type Settings struct {
	Id               bson.ObjectId      `json:"_id" bson:"_id"`
	OpenRegistration bool               `json:"open_registration" bson:"open_registration"`
	UserDetails      []CustomUserDetail `json:"user_details" bson:"user_details"`
	Groups           []string           `json:"groups" bson:"groups"`
	HelpText         string             `json:"help_text" bson:"help_text"`
}

var mongo *mgo.Session
var appDir = "./app"
var store = sessions.NewCookieStore([]byte("lts-cookie-store"))
var loc *time.Location

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

		defer r.Body.Close()

		var m map[string]interface{}
		if r.Header.Get("Content-Type") == "application/json" {
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&m); err != nil {
				log.Println(r.URL, r.RemoteAddr, "JSON decoding error:", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if m == nil {
			m = make(map[string]interface{})
		}

		if err := r.ParseForm(); err != nil {
			log.Println(r.URL, r.RemoteAddr, "Could not parse form:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, param := range required {
			if _, ok := m[param]; !ok {
				formVal := r.FormValue(param)
				if formVal == "" {
					log.Println(r.URL, r.RemoteAddr, "missing_parameter:", param)
					http.Error(w, "missing_parameter", http.StatusBadRequest)
					return
				}
			}
		}
		for key, values := range r.Form {
			if len(values) > 0 {
				m[key] = values[0]
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

func getSettings() (*Settings, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("settings")

	var settings Settings
	if err := c.Find(nil).One(&settings); err != nil {
		if err.Error() == "not found" {
			settings.OpenRegistration = true
		} else {
			return nil, err
		}
	}

	return &settings, nil
}

func signupHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	settings, err := getSettings()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	isAdmin := (sess.Values["level"] == "admin")
	if !settings.OpenRegistration && !isAdmin {
		return http.StatusBadRequest, errors.New("open_registration_disallowed")
	}

	username := strings.TrimSpace(m["username"].(string))
	password := m["password"].(string)

	if len(username) < 4 {
		return http.StatusBadRequest, errors.New("invalid_username")
	}
	if len(password) < 6 {
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

	if !isAdmin {
		saveSession(w, r, &user)
	}
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
	if user.Disabled {
		return http.StatusUnauthorized, errors.New("account_disabled")
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

func checkUniqueField(username, key, value string) error {
	settings, err := getSettings()
	if err != nil || len(settings.UserDetails) == 0 {
		return nil
	}
	isUnique := false
	for _, field := range settings.UserDetails {
		if field.Name == key {
			isUnique = field.Unique
			break
		}
	}
	if !isUnique {
		return nil
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")
	var user User
	if err := c.Find(bson.M{
		"username": bson.M{"$ne": username},
		"custom": bson.M{
			"$elemMatch": bson.M{
				"name":  key,
				"value": value,
			},
		},
	}).One(&user); err != nil {
		if err.Error() == "not found" {
			return nil
		}
		return err
	}
	return errors.New("value_not_unique")
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

	updateObj := bson.M{
		"name":           name,
		"email":          email,
		"street_address": streetAddress,
		"postal_code":    postalCode,
		"phone_number":   phoneNumber,
	}
	if val, ok := m["custom"]; ok {
		customArr := m["custom"].([]interface{})
		for _, v := range customArr {
			obj := v.(map[string]interface{})
			objName := obj["name"].(string)
			objVal := obj["value"].(string)
			if err := checkUniqueField(sess.Values["username"].(string), objName, objVal); err != nil {
				return http.StatusBadRequest, err
			}
		}
		updateObj["custom"] = val
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	if err := c.Update(bson.M{"username": sess.Values["username"]}, bson.M{"$set": updateObj}); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func updateUserPasswordHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	newPassword := m["new_password"].(string)

	if len(newPassword) < 6 {
		return http.StatusBadRequest, errors.New("short_password")
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	checkCurrentPassword := true
	isAdmin := (sess.Values["level"] == "admin")
	username := sess.Values["username"]
	if isAdmin {
		if val, ok := m["username"]; ok {
			username = val.(string)
			checkCurrentPassword = false
		}
	}

	if checkCurrentPassword {
		currentPassword := m["current_password"].(string)
		var user bson.M
		if err := c.Find(bson.M{"username": username}).One(&user); err != nil {
			return http.StatusInternalServerError, err
		}
		if !checkPasswordHash(currentPassword, user["password"].(string)) {
			return http.StatusUnauthorized, errors.New("invalid_current_password")
		}
	}

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if err := c.Update(bson.M{"username": username}, bson.M{
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
		"name":                m["name"].(string),
		"booking_text":        m["booking_text"].(string),
		"max_booking_length":  int(m["max_booking_length"].(float64)),
		"max_bookings":        int(m["max_bookings"].(float64)),
		"cancellation_period": int(m["cancellation_period"].(float64)),
		"week_days_open":      int(m["week_days_open"].(float64)),
		"week_days_close":     int(m["week_days_close"].(float64)),
		"saturday_open":       int(m["saturday_open"].(float64)),
		"saturday_close":      int(m["saturday_close"].(float64)),
		"sunday_open":         int(m["sunday_open"].(float64)),
		"sunday_close":        int(m["sunday_close"].(float64)),
		"group":               m["group"].(string),
		"hour_precision":      m["hour_precision"].(bool),
	}

	if val, ok := m["targets"]; ok {
		targets := val.([]interface{})
		newTargets := make([]bson.ObjectId, len(targets))
		for i, target := range targets {
			targetStr := target.(string)
			if !bson.IsObjectIdHex(targetStr) {
				return http.StatusNotFound, errors.New("not_found")
			}
			newTargets[i] = bson.ObjectIdHex(targetStr)
		}
		data["targets"] = newTargets
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
	begin, err := time.ParseInLocation(shortForm, beginStr+" 00:00:00", loc)
	if err != nil {
		return http.StatusBadRequest, err
	}
	end, err := time.ParseInLocation(shortForm, endStr+" 23:59:59", loc)
	if err != nil {
		return http.StatusBadRequest, err
	}
	recurring := false
	if val, ok := m["recurring"]; ok {
		recurring = val.(bool)
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("bookings")

	find := bson.M{
		"end": bson.M{"$lte": end},
	}
	if !recurring {
		find["begin"] = bson.M{"$gte": begin}
	} else {
		find["$or"] = []bson.M{
			bson.M{
				"begin": bson.M{"$gte": begin},
			},
			bson.M{
				"weekday": int(begin.Weekday()),
			},
		}
	}

	fields := bson.M{
		"_id":      1,
		"court_id": 1,
		"begin":    1,
		"end":      1,
		"title":    1,
		"weekday":  1,
		"parent":   1,
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

	settings, err := getSettings()
	if err != nil || len(settings.UserDetails) == 0 {
		return true
	}

	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")
	var user User
	if err := c.Find(bson.M{"username": sess.Values["username"]}).One(&user); err != nil {
		return false
	}

	for _, detail := range settings.UserDetails {
		userVal := ""
		for _, val := range user.Custom {
			if val.Name == detail.Name {
				userVal = val.Value
				break
			}
		}

		if detail.Dependency == nil || len(detail.Dependency.Name) == 0 {
			if userVal == "" {
				return false
			}
		} else {
			dependencyVal := ""
			for _, val := range user.Custom {
				if val.Name == detail.Dependency.Name {
					dependencyVal = val.Value
					break
				}
			}
			if dependencyVal == "" {
				return false
			}
			if dependencyVal == detail.Dependency.Value && userVal == "" {
				return false
			}
		}
	}

	return true
}

func isCourtBooked(id bson.ObjectId, begin, end time.Time, c *mgo.Collection) (bool, error) {
	var bookings []Booking
	if err := c.Find(bson.M{
		"court_id": id,
		"$or": []bson.M{
			bson.M{
				"begin": bson.M{"$lt": end},
				"end":   bson.M{"$gt": begin},
			},
			bson.M{
				"weekday": int(begin.Weekday()),
			},
		},
	}).All(&bookings); err != nil {
		return false, err
	}

	tBegin := begin.Hour()*60 + begin.Minute()
	tEnd := end.Hour()*60 + end.Minute()
	for _, b := range bookings {
		bBeginLoc := b.Begin.In(loc)
		bEndLoc := b.End.In(loc)
		bBegin := bBeginLoc.Hour()*60 + bBeginLoc.Minute()
		bEnd := bEndLoc.Hour()*60 + bEndLoc.Minute()
		if tBegin < bEnd && tEnd > bBegin {
			return true, nil
		}
	}

	return false, nil
}

var bookHandlerMutex sync.Mutex

func bookHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	isAdmin := (sess.Values["level"] == "admin")
	if !isAdmin && !hasFullUserDetails(sess) {
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

	var court Court
	if err := c.Find(bson.M{"_id": courtId}).One(&court); err != nil {
		return http.StatusNotFound, err
	}
	courtIds := court.Targets
	courtIds = append(courtIds, courtId)

	dayOfWeek := -1
	title := sess.Values["name"]
	if isAdmin {
		if val, ok := m["title"]; ok {
			title = val.(string)
		}
		recurring := m["recurring"].(bool)
		if recurring {
			dayOfWeek = int(begin.Weekday())
		}
	}

	// Checking that the court is free and inserting the booking needs to be
	// one atomic operation.
	bookHandlerMutex.Lock()
	defer bookHandlerMutex.Unlock()

	for _, cId := range courtIds {
		c = s.DB("").C("courts")
		if err := c.Find(bson.M{
			"_id":      cId,
			fieldOpen:  bson.M{"$lte": beginNum},
			fieldClose: bson.M{"$gte": endNum},
		}).One(&court); err != nil {
			return http.StatusBadRequest, errors.New("court_unavailable")
		}

		if !isAdmin && court.MaxBookingLength*60 < (endNum-beginNum) {
			return http.StatusBadRequest, errors.New("max_booking_length_exceeded")
		}

		c = s.DB("").C("bookings")
		isBooked, err := isCourtBooked(cId, begin, end, c)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		if isBooked {
			return http.StatusBadRequest, errors.New("court_already_booked")
		}

		if !isAdmin {
			// find number of future bookings to this court
			count, err := c.Find(bson.M{
				"username": sess.Values["username"],
				"court_id": cId,
				"begin":    bson.M{"$gt": now},
			}).Count()
			if err != nil {
				return http.StatusInternalServerError, err
			}
			if count >= court.MaxBookings {
				return http.StatusBadRequest, errors.New("max_bookings_exceeded")
			}
		}
	}

	parentId := bson.NewObjectId()
	for _, cId := range courtIds {
		booking := bson.M{
			"username":   sess.Values["username"],
			"title":      title,
			"court_id":   cId,
			"begin":      begin,
			"end":        end,
			"created_at": &now,
			"weekday":    dayOfWeek,
		}
		var id bson.ObjectId
		if cId != courtId {
			id = bson.NewObjectId()
			booking["parent"] = &parentId
		} else {
			id = parentId
		}
		booking["_id"] = id
		if err := c.Insert(booking); err != nil {
			return http.StatusInternalServerError, err
		}
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
	var booking Booking
	if err := c.Find(bson.M{"_id": id}).One(&booking); err != nil {
		return http.StatusNotFound, err
	}

	c = s.DB("").C("courts")
	var court Court
	if err := c.Find(bson.M{"_id": booking.CourtId}).One(&court); err != nil {
		return http.StatusInternalServerError, err
	}

	c = s.DB("").C("bookings")
	fields := bson.M{"_id": id}
	if sess.Values["level"] != "admin" {
		fields["username"] = sess.Values["username"]
		fields["begin"] = bson.M{"$gt": time.Now().Add(time.Hour * time.Duration(court.CancellationPeriod))}
	}

	if err := c.Remove(fields); err != nil {
		return http.StatusBadRequest, err
	}
	if _, err := c.RemoveAll(bson.M{"parent": id}); err != nil {
		return http.StatusInternalServerError, err
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

func deleteUserHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	if err := c.Remove(bson.M{"username": m["username"].(string)}); err != nil {
		return http.StatusBadRequest, err
	}

	return http.StatusOK, nil
}

func usersCsvHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	settings, err := getSettings()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	var users []User
	if err := c.Find(nil).All(&users); err != nil {
		return http.StatusNotFound, err
	}

	w.Header().Set("Content-Disposition", "attachment; filename=users.csv")
	w.Header().Set("Content-Type", "text/csv")
	csvWriter := csv.NewWriter(w)
	csvWriter.Comma = ';'

	record := []string{
		"Käyttäjänimi",
		"Nimi",
		"Sähköposti",
		"Katuosoite",
		"Postinumero",
		"Puhelinnumero",
		"Luontipäivämäärä",
	}
	for _, f1 := range settings.UserDetails {
		record = append(record, f1.Name)
	}
	if err := csvWriter.Write(record); err != nil {
		return http.StatusInternalServerError, err
	}

	for _, user := range users {
		if user.Disabled {
			continue
		}
		record := []string{
			user.Username,
			user.Name,
			user.Email,
			user.StreetAddress,
			user.PostalCode,
			user.PhoneNumber,
			user.CreatedAt.In(loc).Format("02.01.2006 15:04:05"),
		}
		for _, f1 := range settings.UserDetails {
			for _, f2 := range user.Custom {
				if f2.Name == f1.Name {
					record = append(record, f2.Value)
					break
				}
			}
		}
		if err := csvWriter.Write(record); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	csvWriter.Flush()

	return http.StatusOK, nil
}

func userDetailsHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	var user User
	if err := c.Find(bson.M{"username": sess.Values["username"]}).One(&user); err != nil {
		return http.StatusNotFound, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func settingsHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	settings, err := getSettings()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(settings); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func updateSettingsHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("settings")

	obj := bson.M{}
	if val, ok := m["open_registration"]; ok {
		obj["open_registration"] = val
	}

	if val, ok := m["user_details"]; ok {
		obj["user_details"] = val
	}

	if val, ok := m["groups"]; ok {
		obj["groups"] = val
	}

	if val, ok := m["help_text"]; ok {
		obj["help_text"] = val
	}

	if val, ok := m["unique"]; ok {
		obj["unique"] = val
	}

	if _, err := c.Upsert(nil, bson.M{"$set": obj}); err != nil {
		return http.StatusNotFound, err
	}

	return http.StatusOK, nil
}

func updateUserDisabledHandler(w http.ResponseWriter, r *http.Request, m map[string]interface{}, sess *sessions.Session) (int, error) {
	s := mongo.Copy()
	defer s.Close()
	c := s.DB("").C("users")

	if err := c.Update(bson.M{
		"username": m["username"].(string),
	}, bson.M{
		"$set": bson.M{
			"disabled": m["disabled"].(bool),
		},
	}); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, appDir+"/index.html")
}

func addIndexes(s *mgo.Session) error {
	m := make(map[string][]mgo.Index)

	m["users"] = append(m["users"], mgo.Index{
		Key:    []string{"username"},
		Unique: true,
	})
	m["courts"] = append(m["courts"], mgo.Index{
		Key:    []string{"name"},
		Unique: true,
	})
	m["bookings"] = append(m["bookings"], mgo.Index{
		Key:    []string{"begin"},
		Unique: false,
	})
	m["bookings"] = append(m["bookings"], mgo.Index{
		Key:    []string{"end"},
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

func main() {
	var err error

	loc, err = time.LoadLocation("Europe/Helsinki")
	if err != nil {
		log.Panic("Unable to set IANA location:", err)
	}

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
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(os.Getenv("LTS_BOOKING_DOMAIN")),
		Cache:      autocert.DirCache("certs"),
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
		"court_id", "date", "time_begin", "time_end", "recurring"))
	http.HandleFunc("/api/cancel_booking", myHandler(cancelBookingHandler, "user", "_id"))
	http.HandleFunc("/api/set_booking_payment", myHandler(setBookingPaymentHandler, "admin",
		"_id", "payment_type"))
	http.HandleFunc("/api/update_user_password", myHandler(updateUserPasswordHandler, "user", "new_password"))
	http.HandleFunc("/api/user", myHandler(userHandler, "admin", "username"))
	http.HandleFunc("/api/users", myHandler(usersHandler, "admin"))
	http.HandleFunc("/api/user_details", myHandler(userDetailsHandler, "user"))
	http.HandleFunc("/api/settings", myHandler(settingsHandler, ""))
	http.HandleFunc("/api/update_settings", myHandler(updateSettingsHandler, "admin"))
	http.HandleFunc("/api/update_user_disabled", myHandler(updateUserDisabledHandler, "admin", "username", "disabled"))
	http.HandleFunc("/api/users_csv", myHandler(usersCsvHandler, "admin"))
	http.HandleFunc("/api/delete_user", myHandler(deleteUserHandler, "admin", "username"))

	port := os.Getenv("LTS_BOOKING_PORT")
	if port != "" {
		log.Println("Listening at localhost:" + port)
		err = http.ListenAndServe(":"+port, context.ClearHandler(http.DefaultServeMux))
	} else {
		go http.ListenAndServe(":http", certManager.HTTPHandler(nil))

		server := &http.Server{
			Addr:    ":https",
			Handler: context.ClearHandler(http.DefaultServeMux),
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		log.Println("Listening at port 443, domain", os.Getenv("LTS_BOOKING_DOMAIN"))
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		log.Println(err)
	}
}
