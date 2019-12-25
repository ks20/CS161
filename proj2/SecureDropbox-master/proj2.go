package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
/*func someUsefulThings() {
	userlib.SetDebugStatus(false)
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	// userlib.DebugMsg("UUID as string:%v", f.String())

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
}*/

/*
********************************************
**             Helper Functions           **
********************************************
*/

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
/*func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}*/

func encryptData(plaintext []byte, encryptionKey []byte, macKey []byte) (data [] byte, err error) {
	var result = make([]byte, 0)
	iv := userlib.RandomBytes(16)
	edata := userlib.SymEnc(encryptionKey, iv, plaintext)
	macMsg := append(iv, edata...)
	tag, err := userlib.HMACEval(macKey, macMsg)
	if err != nil { return nil, err }

	result = append(append(iv, edata...), tag...)
	return result, err
}

func decryptData(ciphertext []byte, encryptionKey []byte, macKey []byte) (data []byte, err error) {
	// Seperate Ciphtertext
	lenCiphertext := len(ciphertext)

	iv := ciphertext[:16]
	encryptedData := ciphertext[16:lenCiphertext-64]
	tag := ciphertext[lenCiphertext-64:lenCiphertext]

	// Compute MAC, Verify Tag
	computedMAC, err := userlib.HMACEval(macKey, append(iv, encryptedData...))
	if err != nil { return nil, err }
	isUncorrupted := userlib.HMACEqual(tag, computedMAC)
	if !isUncorrupted { return nil, err }

	// Unencrypt Data
	data = userlib.SymDec(encryptionKey, encryptedData)

	return data, err
}

func saveUserStruct(userdata *User) (err error) {
	byteUserData, err := json.Marshal(userdata)
	if err != nil { return err }

	uuidDatastoreKey, err := uuid.FromBytes(userdata.UuidSeed)
	if err != nil { return err }

	edata, err := encryptData(byteUserData, userdata.EncryptionKey, userdata.MacKey)
	if err != nil { return err }
	
	userlib.DatastoreSet(uuidDatastoreKey, edata)

	return
}

/** Getting Data from Datastore and Decrypting **/
// value, ok := userlib.DatastoreGet(key)
// if !ok { return nil, errors.New("Unable to retrieve file from Datastore – Try Again") }
// data, err := decryptData(ciphertext, encryptionKey, macKey)
// if err != nil { return nil, err }

/** Encrypting and Setting Data for the Datastore **/
// edata, err := encryptData(data, encryptionKey, macKey)
// if err != nil { return nil, err }
// userlib.DatastoreSet(key, edata)

/** Getting Struct Data **/
// var dataStruct STRUCT_TYPE
// err = json.Unmarshal(data, &dataStruct)
// if err != nil { return nil, errors.New("Problem converting []byte to struct") }

/** Setting Struct Data **/
// byteData, err := json.Marshal(data)
// if err != nil { return nil, errors.New("Problem converting struct to []byte") }

// The structure definition for a user record
type User struct {
	MacKey []byte
	EncryptionKey []byte
	UuidSeed []byte

	RSAEncryptionPrivateKey userlib.PKEDecKey
	DSSigningKey userlib.DSSignKey
	FileDirectory map[string]MetadataKeysAndLocation
}

type MetadataKeysAndLocation struct {
	EncryptionKey []byte
	MacKey []byte
	Location uuid.UUID
}

type FileMetadata struct {
	EncryptionKey []byte
	MacKey []byte
	DatastoreKeys []uuid.UUID
}

// This creates a user. It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Populate the User Struct	
	rsaEncKey, rsaDecKey, err := userlib.PKEKeyGen()
	if err != nil { return nil, err }
	err = userlib.KeystoreSet(username + "rsaEncKey", rsaEncKey)
	if err != nil { return nil, err }
	userdata.RSAEncryptionPrivateKey = rsaDecKey

	dsSignKey, dsVerifyKey, err := userlib.DSKeyGen()
	if err != nil { return nil, err }
	err = userlib.KeystoreSet(username + "dsVerifyKey", dsVerifyKey)
	if err != nil { return nil, err }
	userdata.DSSigningKey = dsSignKey

	//userdata.FileDirectory = make(map[string]FileMetadata)
	userdata.FileDirectory = make(map[string]MetadataKeysAndLocation)

	// Create Encryption Keys for User Struct
	keys := userlib.Argon2Key([]byte(password), []byte(username), 48)

	userdata.MacKey = keys[:16]
	userdata.EncryptionKey = keys[16:32]
	userdata.UuidSeed = keys[32:]

	// Encrypt and Store User Struct
	saveUserStruct(&userdata)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Derive keys
	keys := userlib.Argon2Key([]byte(password), []byte(username), 48)
	macKey := keys[:16]
	encryptionKey := keys[16:32]
	uuidSeed := keys[32:]

	uuidDatastoreKey, err := uuid.FromBytes(uuidSeed)
	if err != nil { return nil, err }

	// Decrypting, unmarshalling struct
	encryptedData, okBool := userlib.DatastoreGet(uuidDatastoreKey)
	if !okBool { return nil, errors.New(strings.ToTitle("Cannot retrieve from data store."))}
	decryptedData, err := decryptData(encryptedData, encryptionKey, macKey)
	if err != nil { return nil, err }
	err = json.Unmarshal(decryptedData, &userdataptr) //goes from encrypted bytes to encrypted user struct
	if err != nil { return nil, err }

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Populate FileMetadata struct
	var fileMetadata FileMetadata
	fileMetadata.EncryptionKey = userlib.RandomBytes(16)
	fileMetadata.MacKey = userlib.RandomBytes(16)

	uuidDatastoreKey := uuid.New()
	fileMetadata.DatastoreKeys = []userlib.UUID{uuidDatastoreKey}

	// Add the location of the metadata struct to User struct
	var metadataKeysAndLocation MetadataKeysAndLocation // ADJUSTED
	metadataKeysAndLocation.EncryptionKey = userlib.RandomBytes(16) // ADJUSTED
	metadataKeysAndLocation.MacKey = userlib.RandomBytes(16) // ADJUSTED
	metadataKeysAndLocation.Location = uuid.New() // ADJUSTED
	userdata.FileDirectory[filename] = metadataKeysAndLocation // ADJUSTED

	// Save the User struct with updated information in the Datastore
	saveUserStruct(userdata)

	// Encrypt and Store File and the Metadata Struct in Datastore
	edata, err := encryptData(data, fileMetadata.EncryptionKey, fileMetadata.MacKey)
	if err != nil { return }
	userlib.DatastoreSet(uuidDatastoreKey, edata)

	byteFileMetadata, err := json.Marshal(fileMetadata)
	if err != nil { return }
	efdata, err := encryptData(byteFileMetadata, metadataKeysAndLocation.EncryptionKey, metadataKeysAndLocation.MacKey) // ADJUSTED
	userlib.DatastoreSet(metadataKeysAndLocation.Location, efdata) // ADJUSTED
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Get the MetadataKeysAndLocation 
	var metadataKeysAndLocation MetadataKeysAndLocation // ADJUSTED
	metadataKeysAndLocation, ok := userdata.FileDirectory[filename] // ADJUSTED
	if !ok { return errors.New("File does not exist") } // ADJUSTED

	// Get correct file from FileDirectory
	var fileMetadata FileMetadata // ADJUSTED
	efdata, ok := userlib.DatastoreGet(metadataKeysAndLocation.Location) // ADJUSTED
	if !ok { return errors.New("Unable to retrieve Metadatafile from Datastore – Try Again") } // ADJUSTED
	fdata, err := decryptData(efdata, metadataKeysAndLocation.EncryptionKey, metadataKeysAndLocation.MacKey) // ADJUSTED
	if err != nil { return err } // ADJUSTED
	err = json.Unmarshal(fdata, &fileMetadata) // ADJUSTED
	if err != nil { return err } // ADJUSTED

	// Create new location and add it to the FileMetadata struct
	uuidDatastoreKey := uuid.New()
	fileMetadata.DatastoreKeys = append(fileMetadata.DatastoreKeys, uuidDatastoreKey)
	
	// Save the FileMetadata struct with updated information in the Datastore
	byteFileMetadata, err := json.Marshal(fileMetadata) // ADJUSTED
	if err != nil { return } // ADJUSTED
	efdata, err = encryptData(byteFileMetadata, metadataKeysAndLocation.EncryptionKey, metadataKeysAndLocation.MacKey) // ADJUSTED
	userlib.DatastoreSet(metadataKeysAndLocation.Location, efdata) // ADJUSTED

	// Encrypt and store new data to the location
	edata, err := encryptData(data, fileMetadata.EncryptionKey, fileMetadata.MacKey) // ADJUSTED
	if err != nil { return err } // ADJUSTED
	userlib.DatastoreSet(uuidDatastoreKey, edata) // ADJUSTED

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Get the MetadataKeysAndLocation 
	var metadataKeysAndLocation MetadataKeysAndLocation // ADJUSTED
	metadataKeysAndLocation, ok := userdata.FileDirectory[filename] // ADJUSTED
	if !ok { return nil, errors.New("File does not exist") } // ADJUSTED

	// Get FileMetadata
	var fileMetadata FileMetadata // ADJUSTED
	efdata, ok := userlib.DatastoreGet(metadataKeysAndLocation.Location) // ADJUSTED
	if !ok { return nil, errors.New("Unable to retrieve Metadatafile from Datastore – Try Again") } // ADJUSTED
	fdata, err := decryptData(efdata, metadataKeysAndLocation.EncryptionKey, metadataKeysAndLocation.MacKey) // ADJUSTED
	if err != nil { return nil, err } // ADJUSTED
	err = json.Unmarshal(fdata, &fileMetadata) // ADJUSTED
	if err != nil { return nil, err } // ADJUSTED

	// Iterate through the DatastoreKey entries and append to the data
	datastoreKeys := fileMetadata.DatastoreKeys
	for i := 0; i < len(datastoreKeys); i++ {
		uuidDatastoreKey := datastoreKeys[i]

		// Retrieve and decrypt data
		edata, ok := userlib.DatastoreGet(uuidDatastoreKey)
		if !ok { return nil, errors.New("Unable to retrieve file from Datastore – Try Again") }
		tempData, err := decryptData(edata, fileMetadata.EncryptionKey, fileMetadata.MacKey)
		if err != nil { return nil, err }

		// Append data
		data = append(data, tempData...)
	}
    
	return data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.

// type sharingRecord struct {
// 	EncryptionKey []byte
// 	MacKey []byte
// 	Location uuid.UUID
// }

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	// Get FileMetadata
	var metadataKeysAndLocation MetadataKeysAndLocation // ADJUSTED
	metadataKeysAndLocation, ok := userdata.FileDirectory[filename] // ADJUSTED
	if !ok { return "", errors.New("File does not exist") } // ADJUSTED

	// Save the location of the metadata file to send in the magic string
	location := metadataKeysAndLocation.Location
	encryptionKey := metadataKeysAndLocation.EncryptionKey
	macKey := metadataKeysAndLocation.MacKey
	byteLocation, err := json.Marshal(location)
	if err != nil { return "", err }
	unencrypted_magic_string := append(byteLocation, append(encryptionKey, macKey...)...)

	// RSA encrypt the magic_string
	publicKey, ok := userlib.KeystoreGet(recipient + "rsaEncKey")
	if !ok { return "", errors.New("Unable to get RSA public key for recipient – Try Again") }
	e_magic_string, err := userlib.PKEEnc(publicKey, unencrypted_magic_string)
	if err != nil { return "", err }

	// Sign the magic string
	s_magic_string, err := userlib.DSSign(userdata.DSSigningKey, e_magic_string)
	if err != nil { return "", err }

	es_magic_string := append(e_magic_string, s_magic_string...)

	return hex.EncodeToString(es_magic_string), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	// Trigger error if filename is already in use
	_, ok := userdata.FileDirectory[filename]
	if ok { return errors.New("Filename already in use") }

	// Get and separate magic string
	byteString, err := hex.DecodeString(magic_string)
	if err != nil { return err }

	e_magic_string := byteString[:256]
	s_magic_string := byteString[256:]

	// Verify magic string
	vk, ok := userlib.KeystoreGet(sender + "dsVerifyKey")
	if !ok { return errors.New("Unable to retrive DS VerifyKey from Keystore") }
	err = userlib.DSVerify(vk, e_magic_string, s_magic_string)
	if err != nil { return err }

	// Decrypt magic string
	dk := userdata.RSAEncryptionPrivateKey
	unencrypted_magic_string, err := userlib.PKEDec(dk, e_magic_string)
	if err != nil { return err }	

	// Separate magic string into component parts
	var location uuid.UUID
	err = json.Unmarshal(unencrypted_magic_string[:38], &location)
	if err != nil { return err }
	encryptionKey := unencrypted_magic_string[38:54]
	macKey := unencrypted_magic_string[54:]

	// save MetadataKeysAndLocation
	var metadataKeysAndLocation MetadataKeysAndLocation
	metadataKeysAndLocation.Location = location
	metadataKeysAndLocation.EncryptionKey = encryptionKey
	metadataKeysAndLocation.MacKey = macKey

	// Save FileMetadata struct to the FileDirectory
	userdata.FileDirectory[filename] = metadataKeysAndLocation

	// Save UserData struct
	saveUserStruct(userdata)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// Get the file data
	fileData, err := userdata.LoadFile(filename)
	if err != nil { return err }

	// Retrieve FileMetadata struct from FileDirectory
	var metadataKeysAndLocation MetadataKeysAndLocation // ADJUSTED
	metadataKeysAndLocation, ok := userdata.FileDirectory[filename] // ADJUSTED

	//var fileMetadata FileMetadata
	//fileMetadata, ok := userdata.FileDirectory[filename]
	if !ok { return errors.New("FileMetadata does not exist") }

	// Delete all file data in datastore
	var loc = metadataKeysAndLocation.Location
	userlib.DatastoreDelete(loc)

	// generating the new keys, create new filemetadatastruct, overwrite
	userdata.StoreFile(filename, fileData) 
	//save userdata struct
	saveUserStruct(userdata)
	return
}
