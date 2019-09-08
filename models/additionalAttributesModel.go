package models

import "github.com/dunv/uauth/interfaces"

var AdditionalAttributesModel interfaces.AdditionalUserAttributesInterface

func SetAdditionalAttributesModel(model interfaces.AdditionalUserAttributesInterface) {
	AdditionalAttributesModel = model
}
