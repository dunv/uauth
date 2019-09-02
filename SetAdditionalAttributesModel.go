package uauth

var additionalAttributesModel AdditionalUserAttributesInterface

func SetAdditionalAttributesModel(model AdditionalUserAttributesInterface) {
	additionalAttributesModel = model
}

type AdditionalUserAttributesInterface interface {
	CloneEmpty() AdditionalUserAttributesInterface
}
