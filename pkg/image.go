package pkg

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/tjarratt/babble"
)

func (a *API) getAllImages(w http.ResponseWriter, r *http.Request) {
	var images []Image

	if err := a.Options.DB.Find(&images).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Unable to retrieve all images"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, images)
}

func (a *API) getImage(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	imageSlug := params["imageSlug"]
	var image Image

	if err := a.Options.DB.Table("images").Where("slug = ?", imageSlug).First(&image).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Image not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, image)
}

func (a *API) createImage(w http.ResponseWriter, r *http.Request) {
	var image Image

	if err := json.NewDecoder(r.Body).Decode(&image); err != nil {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	// Validate request once more
	if image.PostedBy == 0 || image.Source == "" {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	// Set random slug
	image.Slug = strings.ToLower(babble.NewBabbler().Babble())

	if err := a.Options.DB.Create(&image).Error; err != nil {
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to create image"))
		return
	}

	respond(w, image)
}

func (a *API) updateImage(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	imageSlug := params["imageSlug"]
	var image Image

	if err := json.NewDecoder(r.Body).Decode(&image); err != nil {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	// Validate request once more
	if image.PostedBy == 0 || image.Source == "" {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	if err := a.Options.DB.Table("images").Where("slug = ?", imageSlug).First(&image).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Image not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	if err := a.Options.DB.Save(&image).Error; err != nil {
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to update image"))
		return
	}

	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("Image %v successfully updated", imageSlug)))
}

func (a *API) deleteImage(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	imageSlug := params["imageSlug"]
	var image Image

	if err := a.Options.DB.Table("images").Where("slug = ?", imageSlug).Delete(&image).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Image not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("Image %v successfully deleted", imageSlug)))
}
