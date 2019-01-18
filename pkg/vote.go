package pkg

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
)

func (a *API) getVote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	voteID := params["voteId"]
	var vote Vote

	if err := a.Options.DB.Table("votes").Where("id = ?", voteID).First(&vote).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Vote not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, vote)
}

// TODO add validation and increment Image's vote value
func (a *API) createVote(w http.ResponseWriter, r *http.Request) {
	var vote Vote

	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	if err := a.Options.DB.Create(&vote).Error; err != nil {
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to create vote"))
		return
	}

	respond(w, vote)
}

func (a *API) updateVote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	voteID := params["voteId"]
	var vote Vote

	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	if err := a.Options.DB.Table("votes").Where("id = ?", voteID).First(&vote).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Vote not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	if err := a.Options.DB.Save(&vote).Error; err != nil {
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to update vote"))
		return
	}

	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("Vote %v successfully updated", voteID)))
}

func (a *API) deleteVote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	voteID := params["voteId"]
	var vote Vote

	if err := a.Options.DB.Table("votes").Where("id = ?", voteID).Delete(&vote).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			respond(w, jsonResponse(http.StatusNotFound, "Vote not found"))
			return
		}
		respond(w, jsonResponse(http.StatusInternalServerError, "Database connection error"))
		return
	}

	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("Vote %v successfully deleted", voteID)))
}
