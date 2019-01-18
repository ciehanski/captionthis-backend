package pkg

import "errors"

// OS Exit Codes
const (
	ErrInitilizing        = 1
	ErrClosingDatabase    = 2
	ErrShuttingDownServer = 3
	ErrStartingServer     = 4
)

// Application Errors
var (
	// System Errors
	ErrDatabase    = errors.New("Database error")
	ErrNilDatabase = errors.New("Database information must not be nil")
	ErrBadRequest  = errors.New("Bad request")
	// User Errors
	ErrInvalidTokenAndUser        = errors.New("User token does not match user ID provided")
	ErrInvalidRefreshAndUser      = errors.New("Refresh token does not match user ID provided")
	ErrCreatingTokens             = errors.New("Error creating authentication token")
	ErrValidatingPassword         = errors.New("Error validating password")
	ErrIncorrectPassword          = errors.New("Incorrect password")
	ErrUserNotFound               = errors.New("User not found")
	ErrInvalidPermissionsToUpdate = errors.New("Invalid permissions to update user")
	ErrUpdateUser                 = errors.New("Error updating user")
	ErrCreateUser                 = errors.New("Error creating user")
	ErrRetrievingAllUsers         = errors.New("Unable to retrieve all users")
	ErrWrongArgonVersion          = errors.New("Incompatible argon2 version")
	ErrInvalidHash                = errors.New("Invalid hash")
	ErrReauthenticate             = errors.New("Error re-authenticating")
	ErrLoggingOut                 = errors.New("Error logging user out")
	// User Validation Errors
	ErrUsernameInUse    = errors.New("Username already in use")
	ErrEmailInUse       = errors.New("Email already in use")
	ErrUsernameSymbols  = errors.New("Username cannot contain symbols")
	ErrInvalidEmail     = errors.New("Invalid email address")
	ErrPasswordTooShort = errors.New("Password must contain at least 8 characters")
	ErrPasswordTooLong  = errors.New("Password cannot exceed 100 characters")
	ErrUsernameTooShort = errors.New("Username must contain at least 3 characters")
	ErrUsernameTooLong  = errors.New("Username cannot exceed 20 characters")
	ErrPasswordSymbol   = errors.New("Password must contain at least one symbol")
	ErrPasswordNum      = errors.New("Password must contain at least one number")
	ErrPasswordCapital  = errors.New("Password must contain at least one capital character")
)
