package pkg

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
)

func (a *API) getAllCaptions(w http.ResponseWriter, r *http.Request) {
	var captions []Caption

	if err := a.Options.DB.Find(&captions).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Unable to retrieve all captions"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, captions)
}

func (a *API) getCaption(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	captionID := params["captionId"]
	var caption Caption

	if err := a.Options.DB.Table("captions").Where("id = ?", captionID).First(&caption).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Caption not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, caption)
}

// TODO add validation
func (a *API) createCaption(w http.ResponseWriter, r *http.Request) {
	var caption Caption

	if err := json.NewDecoder(r.Body).Decode(&caption); err != nil {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	if err := a.Options.DB.Create(&caption).Error; err != nil {
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to create caption"))
		return
	}

	respond(w, caption)
}

func (a *API) updateCaption(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	captionID := params["captionId"]
	var caption Caption

	if err := json.NewDecoder(r.Body).Decode(&caption); err != nil {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	if err := a.Options.DB.Table("captions").Where("id = ?", captionID).First(&caption).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Caption not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	if err := a.Options.DB.Save(&caption).Error; err != nil {
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to update caption"))
		return
	}

	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("Caption %v successfully updated", captionID)))
}

func (a *API) deleteCaption(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	captionID := params["captionId"]
	var caption Caption

	if err := a.Options.DB.Table("captions").Where("id = ?", captionID).Delete(&caption).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Image not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("Image %v successfully deleted", captionID)))
}
