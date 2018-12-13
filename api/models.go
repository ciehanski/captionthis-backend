package api

import (
	"time"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
)

type API struct {
	Options Options
}

type Options struct {
	Version string
	Router  *mux.Router
	DB      *gorm.DB
	DBname  string
	DBhost  string
	DBuser  string
	DBpass  string
	DBssl   string
	Debug   bool
}

type Caption struct {
	ID        uint      `gorm:"primary_key" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Image     uint      `gorm:"type:int;not null;unique_index:idx_captions_image" json:"image"`
	Message   string    `gorm:"type:varchar(255);not null" json:"message"`
	PostedBy  uint      `gorm:"type:int;not null" json:"posted_by"`
	Votes     []Vote    `gorm:"foreignkey:Caption" json:"votes"`
}

type Image struct {
	ID        uint      `gorm:"primary_key" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Slug      string    `gorm:"type:varchar(255);not null;unique;unique_index:idx_images_slug" json:"slug"`
	Source    string    `gorm:"type:varchar(255);not null" json:"source"`
	PostedBy  uint      `gorm:"type:int;not null;unique_index:idx_images_postedby" json:"posted_by"`
	Votes     []Vote    `gorm:"foreignkey:Image" json:"votes"`
	Captions  []Caption `gorm:"foreignkey:Image" json:"captions"`
}

type User struct {
	gorm.Model
	Username       string    `gorm:"type:varchar(20);not null;unique;unique_index:idx_users_username" json:"username"`
	Email          string    `gorm:"type:varchar(255);not null;unique;unique_index:idx_users_email" json:"email"`
	EmailConfirmed bool      `gorm:"type:boolean" json:"emailconfirmed"`
	Password       string    `gorm:"type:varchar(255);not null" json:"password,omitempty"`
	Votes          []Vote    `gorm:"foreignkey:PostedBy" json:"votes"`
	Captions       []Caption `gorm:"foreignkey:PostedBy" json:"captions"`
	Images         []Image   `gorm:"foreignkey:PostedBy" json:"images"`
}

type Vote struct {
	gorm.Model
	PostedBy uint `gorm:"type:int;not null;index:idx_votes_posted_by" json:"posted_by"`
	Value    bool `gorm:"type:boolean;not null" json:"value"`
	Caption  uint `gorm:"type:int" json:"caption"`
	Image    uint `gorm:"type:int" json:"image"`
}
