package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username      string
	Password      string
	FilenameUUID  map[string]userlib.UUID
	FilenameKey   map[string][]byte
	VerifyKey     userlib.PublicKeyType
	SignKey       userlib.PrivateKeyType
	EncryptionKey userlib.PublicKeyType
	DecryptionKey userlib.PrivateKeyType

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {

	if username == "" || password == "" {
		return nil, errors.New("empty username or empty password - please fill them out.")
	}
	var userdata User
	userdataptr = &userdata
	var VerifyKey userlib.DSVerifyKey
	var SignKey userlib.DSSignKey
	SignKey, VerifyKey, _ = userlib.DSKeyGen()
	var EncryptionKey userlib.PKEEncKey
	var DecryptionKey userlib.PKEDecKey
	EncryptionKey, DecryptionKey, _ = userlib.PKEKeyGen()

	//userlib.DebugMsg("UserID initial is: %v", thisUserID)
	//TODO: This is a toy implementation.
	//userdata.Username = username
	//userdata.Password = password
	userByte := []byte(username)
	pwByte := []byte(password)
	//userlib.DebugMsg("user is: %v", userByte)
	//userlib.DebugMsg("pw is: %v", pwByte)
	argonKey := userlib.Argon2Key(pwByte, userByte, 16)
	//userlib.DebugMsg("argonke is: %v", argonKey)
	userdata.Username = username
	userdata.VerifyKey = VerifyKey
	userdata.SignKey = SignKey
	userdata.EncryptionKey = EncryptionKey
	userdata.DecryptionKey = DecryptionKey
	userdata.FilenameUUID = make(map[string]userlib.UUID)
	userdata.FilenameKey = make(map[string][]byte)
	//userlib.DebugMsg("UserInitData is: %v", userdata)
	d, _ := json.Marshal(userdata)
	remainder := len(d) % 16
	pad := make([]byte, 16-remainder)
	for i := 0; i < 16-remainder; i++ {
		pad[i] = byte(16 - remainder)
	}
	newd := append(d, pad...)
	randomBytesValue := userlib.RandomBytes(16)
	SymEncValue := userlib.SymEnc(argonKey, randomBytesValue, newd)

	//userlib.DebugMsg("len(d) is: %v", len(d))
	//userlib.DebugMsg("len(newd) is: %v", len(newd))

	var byteArrayUsername = []byte(username)
	thisUserID, _ := uuid.FromBytes(byteArrayUsername)
	userlib.DatastoreSet(thisUserID, SymEncValue)

	// userlib.KeystoreSet(VerifyUUID.String(), VerifyKey)
	// userlib.KeystoreSet(EncryptionUUID.String(), EncryptionKey)
	//End of toy implementation
	//salt can be username
	// for symmetric encryption, keylen is 16 bytes. sender and receiver use the same key. used for ec and dc
	// CBC. break up message into blocs. encrypt each bloc together and
	// encryupt marshalled data
	// decrypt and then unmarshalled
	// generate the argon2key based on correct password and username

	return &userdata, nil
}

// GetUser is documented at:
//https://cs161.org/proj2/crypto/symmetric_encryption.html
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//need to perform error checks

	var byteArrayUsername = []byte(username)

	byteArrayPassword := []byte(password)
	argonKey := userlib.Argon2Key(byteArrayPassword, byteArrayUsername, 16)

	thisUserID, _ := uuid.FromBytes(byteArrayUsername)

	encrypted, error := userlib.DatastoreGet(thisUserID)
	if !error {
		return nil, errors.New(strings.ToTitle("Username not found!"))
	}
	returnvalue := userlib.SymDec(argonKey, encrypted)

	padlength := returnvalue[len(returnvalue)-1]
	d := returnvalue[0 : len(returnvalue)-int(padlength)]
	//userlib.DebugMsg("returnvalue is: %v", returnvalue)
	//userlib.DebugMsg("d is: %v", d)

	//userlib.DebugMsg("UserID after is: %v", thisUserID)
	//var correctUserdata, _ = userlib.DatastoreGet(thisUserID)
	//userlib.DebugMsg("correctUserdata is: %v", correctUserdata)
	userRet := User{}
	json.Unmarshal(d, &userRet)

	userlib.DebugMsg("Correct. You are now logged in!")

	//userlib.DebugMsg("Incorrect. Please try again.")errors.New(strings.ToTitle("Password Incorrect!"))

	return &userRet, nil
}

type Chunk struct {
	UUID userlib.UUID
	Key  []byte
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	//storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	//jsonData, _ := json.Marshal(data)
	//userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation
	key := userlib.RandomBytes(16)
	remainder := len(data) % 16
	pad := make([]byte, 16-remainder)
	for i := 0; i < 16-remainder; i++ {
		pad[i] = byte(16 - remainder)
	}
	newdata := append(data, pad...)
	u := uuid.New()
	encdata := userlib.SymEnc(key, userlib.RandomBytes(16), newdata)
	userlib.DatastoreSet(u, encdata)
	var c Chunk
	c.UUID = u
	c.Key = key
	var chunkarray []Chunk
	key = userlib.RandomBytes(16)
	u = uuid.New()
	chunkarray = append(chunkarray, c)
	marshalled, _ := json.Marshal(chunkarray)

	remainder = len(marshalled) % 16
	pad = make([]byte, 16-remainder)
	for i := 0; i < 16-remainder; i++ {
		pad[i] = byte(16 - remainder)
	}
	marshalled = append(marshalled, pad...)

	encdata = userlib.SymEnc(key, userlib.RandomBytes(16), marshalled)
	userlib.DatastoreSet(u, encdata)
	userdata.FilenameUUID[filename] = u
	userdata.FilenameKey[filename] = key

	//userlib.DebugMsg("post store uuid: %v", userdata.FilenameUUID)
	//userlib.DebugMsg("post store key: %v", userdata.FilenameKey)
	return nil
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	key := userlib.RandomBytes(16)
	remainder := len(data) % 16
	pad := make([]byte, 16-remainder)
	for i := 0; i < 16-remainder; i++ {
		pad[i] = byte(16 - remainder)
	}
	newdata := append(data, pad...)
	u := uuid.New()
	encdata := userlib.SymEnc(key, userlib.RandomBytes(16), newdata)
	userlib.DatastoreSet(u, encdata)
	var c Chunk
	c.UUID = u
	c.Key = key

	u = userdata.FilenameUUID[filename]
	key = userdata.FilenameKey[filename]

	encdata, _ = userlib.DatastoreGet(u)
	marshalleddata := userlib.SymDec(key, encdata)

	lastbyte := marshalleddata[len(marshalleddata)-1]
	marshalleddata = marshalleddata[0 : len(marshalleddata)-int(lastbyte)]

	chunkarray := []Chunk{}
	json.Unmarshal(marshalleddata, &chunkarray)

	chunkarray = append(chunkarray, c)

	marshalled, _ := json.Marshal(chunkarray)

	remainder = len(marshalled) % 16
	pad = make([]byte, 16-remainder)
	for i := 0; i < 16-remainder; i++ {
		pad[i] = byte(16 - remainder)
	}
	marshalled = append(marshalled, pad...)

	userlib.DatastoreSet(u, marshalled)

	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	// ideas: can check with the owner's version to see if the file matches.

	u := userdata.FilenameUUID[filename]
	key := userdata.FilenameKey[filename]

	encdata, _ := userlib.DatastoreGet(u)
	marshalleddata := userlib.SymDec(key, encdata)

	lastbyte := marshalleddata[len(marshalleddata)-1]
	marshalleddata = marshalleddata[0 : len(marshalleddata)-int(lastbyte)]

	chunkarray := []Chunk{}
	json.Unmarshal(marshalleddata, &chunkarray)

	filedata := make([]byte, 0)

	for i := 0; i < len(chunkarray)-1; i++ {
		chunk := chunkarray[i]
		encdata, _ = userlib.DatastoreGet(chunk.UUID)
		decdata := userlib.SymDec(key, encdata)

		lastbyte := decdata[len(decdata)-1]
		decdata = decdata[0 : len(decdata)-int(lastbyte)]
		filedata = append(filedata, decdata...)
	}

	return filedata, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
//idea: shared files will now be under the username of the sharee.
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
