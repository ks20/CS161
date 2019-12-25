package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/nweaver/cs161-p2/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.SetDebugStatus(false)
	// someUsefulThings()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user (here is MAC Key)", u.MacKey)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestEncryptionAndDecryption(t *testing.T) {
	t.Log("Initialization test")
	userlib.SetDebugStatus(false)

	userlib.DebugMsg("data before:%v", []byte("abc"))
	edata, err := encryptData([]byte("abc"), []byte("1234567891234567"), []byte("1234567891234568"))
	if err != nil {return}
	data, err := decryptData(edata, []byte("1234567891234567"), []byte("1234567891234568"))
	userlib.DebugMsg("data after:%v", data)
}

func TestComprehensive(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil { t.Error("Failed to reload user", err) }
	u2, err := InitUser("ali", "a13d")
	if err != nil { t.Error("Failed to initialize user", err) }
	u3, err := InitUser("kushal", "litness")
	if err != nil { t.Error("Failed to initialize user", err) }
	u4, err := InitUser("akshath", "wowlo")
	if err != nil { t.Error("Failed to initialize user", err) }
	u5, err := InitUser("andrew", "sigep")
	if err != nil { t.Error("Failed to initialize user", err) }

	// StoreFiles
	v1 := []byte("Alice's File")
	u1.StoreFile("file1", v1)

	v2 := []byte("Ali's File")
	u2.StoreFile("file1", v2)

	v3 := []byte("Kushal's File")
	u3.StoreFile("file1", v3)

	v4 := []byte("Akshath's File")
	u4.StoreFile("file1", v4)

	v5 := []byte("Andrew's File")
	u5.StoreFile("file1", v5)


	// LoadFile
	l1, err := u1.LoadFile("file1")
	if err != nil { t.Error("Failed to upload and download", err) }
	if !reflect.DeepEqual(v1, l1) { t.Error("Downloaded file is not the same", v1, l1) }

	l2, err := u2.LoadFile("file1")
	if err != nil { t.Error("Failed to upload and download", err) }
	if !reflect.DeepEqual(v2, l2) { t.Error("Downloaded file is not the same", v2, l2) }

	l3, err := u3.LoadFile("file1")
	if err != nil { t.Error("Failed to upload and download", err) }
	if !reflect.DeepEqual(v3, l3) { t.Error("Downloaded file is not the same", v3, l3) }

	l4, err := u4.LoadFile("file1")
	if err != nil { t.Error("Failed to upload and download", err) }
	if !reflect.DeepEqual(v4, l4) { t.Error("Downloaded file is not the same", v4, l4) }

	l5, err := u5.LoadFile("file1")
	if err != nil { t.Error("Failed to upload and download", err) }
	if !reflect.DeepEqual(v5, l5) { t.Error("Downloaded file is not the same", v5, l5) }

	// AppendFile
	a1 := []byte("random fi")
	u1.StoreFile("file2", a1)

	a2 := []byte("random ")
	u2.StoreFile("file2", a2)

	err = u1.AppendFile("file2", []byte("le"))
	if err != nil { t.Error("Error in process of appending", err) }
	
	err = u2.AppendFile("file2", []byte("fil"))
	if err != nil { t.Error("Error in process of appending", err) }
	err = u2.AppendFile("file2", []byte("e"))
	if err != nil { t.Error("Error in process of appending", err) }

	t1, err := u1.LoadFile("file2")
	if err != nil { t.Error("Failed to load", err) }
	t2, err := u2.LoadFile("file2")
	if err != nil { t.Error("Failed to load", err) }

	if !reflect.DeepEqual(t1, t2) { t.Error("Appended file is not the same", t1, t2) }

	// ShareFile
	var magic_string string

	// Alice shares with Kushal
	magic_string, err = u1.ShareFile("file2", "kushal")
	if err != nil { t.Error("Failed to share the a file", err) }
	
	err = u3.ReceiveFile("kushal_file2", "ali", magic_string) // Should fail
	if err == nil { t.Error("Should have errored, wrong sender", err) }

	err = u3.ReceiveFile("kushal_file2", "alice", magic_string)
	if err != nil { t.Error("Failed to receive the share message", err) }

	s3, err := u3.LoadFile("kushal_file2")
	if err != nil { t.Error("Failed to load the file after sharing", err) }

	if !reflect.DeepEqual(t1, s3) {
		t.Error("Shared file is not the same", t1, s3)
	}

	// Kushal shares with Ali
	magic_string, err = u3.ShareFile("kushal_file2", "ali")
	if err != nil { t.Error("Failed to share the a file", err) }

	err = u2.ReceiveFile("file2", "kushal", magic_string)
	if err == nil { t.Error("Failed throw error because file already exists under that name", err) }

	err = u2.ReceiveFile("ali_file2", "kushal", magic_string)
	if err != nil { t.Error("Failed to receive file", err) }
	
	s2, err := u2.LoadFile("ali_file2")
	if err != nil { t.Error("Failed to load the file after sharing", err) }

	if !reflect.DeepEqual(t1, s2) { t.Error("Shared file is not the same", t1, s2) }
	if !reflect.DeepEqual(s3, s2) { t.Error("Shared file is not the same", s3, s2) }

	// Kushal shares with Akshath
	magic_string, err = u3.ShareFile("kushal_file2", "akshath")
	if err != nil { t.Error("Failed to share the a file", err) }

	err = u4.ReceiveFile("akshath_file2", "kushal", magic_string)
	if err != nil { t.Error("Failed to receive file", err) }

	s4, err := u4.LoadFile("akshath_file2")
	if err != nil { t.Error("Failed to load the file after sharing", err) }

	if !reflect.DeepEqual(t1, s4) { t.Error("Shared file is not the same", t1, s4) }
	if !reflect.DeepEqual(s3, s4) { t.Error("Shared file is not the same", s3, s4) }
	if !reflect.DeepEqual(s2, s4) { t.Error("Shared file is not the same", s2, s4) }

	// Kushal shares with Andrew
	magic_string, err = u3.ShareFile("yolo_file2", "andrew")
	if err == nil { t.Error("Failed to throw an error when Kushal doesn't have the file", err) }

	magic_string, err = u3.ShareFile("kushal_file2", "andrew")
	if err != nil { t.Error("Failed to share the a file", err) }

	err = u5.ReceiveFile("andrew_file2", "kushal", magic_string)
	if err != nil { t.Error("Failed to receive file", err) }

	s5, err := u5.LoadFile("andrew_file2")
	if err != nil { t.Error("Failed to load the file after sharing", err) }

	if !reflect.DeepEqual(t1, s5) { t.Error("Shared file is not the same", t1, s5) }
	if !reflect.DeepEqual(s3, s5) { t.Error("Shared file is not the same", s3, s5) }
	if !reflect.DeepEqual(s2, s5) { t.Error("Shared file is not the same", s2, s5) }
	if !reflect.DeepEqual(s4, s5) { t.Error("Shared file is not the same", s4, s5) }

	// If Ali adds to the file, will everyone see the changes work
	err = u2.AppendFile("ali_file2", []byte("LOL"))
	if err != nil { t.Error("Error in process of appending", err) }

	adt2, err := u2.LoadFile("ali_file2")
	if err != nil { t.Error("Failed to load", err) }

	adt4, err := u4.LoadFile("akshath_file2")
	if err != nil { t.Error("Failed to load", err) }

	adt5, err := u5.LoadFile("andrew_file2")
	if err != nil { t.Error("Failed to load", err) }

	adt1, err := u1.LoadFile("file2")
	if err != nil { t.Error("Failed to load", err) }


	if !reflect.DeepEqual(adt2, adt4) { t.Error("Appended file is not the same", adt2, adt4) }
	if !reflect.DeepEqual(adt2, adt5) { t.Error("Appended file is not the same", adt2, adt5) }
	if !reflect.DeepEqual(adt2, adt1) { t.Error("Appended file is not the same", adt2, adt1) }
	if !reflect.DeepEqual(adt4, adt5) { t.Error("Appended file is not the same", adt4, adt5) }
	if !reflect.DeepEqual(adt4, adt1) { t.Error("Appended file is not the same", adt4, adt1) }
	if !reflect.DeepEqual(adt5, adt1) { t.Error("Appended file is not the same", adt5, adt1) }


	// RevokeFile
	err = u1.RevokeFile("file1")
	if err != nil { t.Error("Even though the file has not been shared - it exists so this should work", err) } 
	err = u1.RevokeFile("fileDoesNotExist")
	if err == nil { t.Error("File should not exist", err) } 
	err = u1.RevokeFile("file2")
	if err != nil { t.Error("Revoke failed", err) }

	// Does Alice still have access to the file?
	af1, err := u1.LoadFile("file2")
	if err != nil { t.Error("Failed to load the file after revoking", err) }
	// Is it the same as with the modification?
	if !reflect.DeepEqual(af1, adt4) { t.Error("Appended file is not the same", af1, adt4) }

	// Can Alice still add to the file and stuff
	err = u1.AppendFile("file2", []byte("LOLOL"))
	if err != nil { t.Error("Error in process of appending", err) }
	atest1, err := u1.LoadFile("file2")
	if !reflect.DeepEqual(append(af1, []byte("LOLOL")...), atest1) { t.Error("Appended file is not the same", append(af1, []byte("LOLOL")...), atest1) }

	_, err = u3.LoadFile("kushal_file2")
	if err == nil { t.Error("Failed to revoke", err) }
	_, err = u2.LoadFile("ali_file2")
	if err == nil { t.Error("Failed to revoke", err) }
	_, err = u4.LoadFile("akshath_file2")
	if err == nil { t.Error("Failed to revoke", err) }
	_, err = u5.LoadFile("andrew_file2")
	if err == nil { t.Error("Failed to revoke", err) }

	// Reload users
	ru1, err := GetUser("alice", "fubar")
	if err != nil { t.Error("Failed to get user", err) }
	ru2, err := GetUser("ali", "a13d")
	if err != nil { t.Error("Failed to get user", err) }
	ru3, err := GetUser("kushal", "litness")
	if err != nil { t.Error("Failed to get user", err) }
	ru4, err := GetUser("akshath", "wowlo")
	if err != nil { t.Error("Failed to get user", err) }
	ru5, err := GetUser("andrew", "sigep")
	if err != nil { t.Error("Failed to get user", err) }

	// Do Files and Sharing permissions from before exist
	
	// Alice
	_, err = ru1.LoadFile("file1")
	if err != nil { t.Error("File1 does not exist", err) }
	h1, err := ru1.LoadFile("file2")
	if err != nil { t.Error("File2 does not exist", err) }

	if !reflect.DeepEqual(h1, atest1) { t.Error("File is not the same upon reload", h1, atest1) }

	// Kushal
	_, err = ru3.LoadFile("file1")
	if err != nil { t.Error("File1 does not exist", err) }
	_, err = ru3.LoadFile("kushal_file2")
	if err == nil { t.Error("kushal_file2 should not exist", err) }

	// Ali
	_, err = ru2.LoadFile("file1")
	if err != nil { t.Error("File1 does not exist", err) }
	rf2, err := ru2.LoadFile("file2")
	if err != nil { t.Error("file2 does not exist", err) }
	if !reflect.DeepEqual(rf2, t2) { t.Error("Shared file is not the same", rf2, t2) }
	_, err = ru2.LoadFile("ali_file2")
	if err == nil { t.Error("ali_file2 should not exist", err) }

	// Akshath
	_, err = ru4.LoadFile("file1")
	if err != nil { t.Error("File1 does not exist", err) }
	_, err = ru4.LoadFile("akshath_file2")
	if err == nil { t.Error("kushal_file2 should not exist", err) }

	// Andrew
	_, err = ru5.LoadFile("file1")
	if err != nil { t.Error("File1 does not exist", err) }
	_, err = ru5.LoadFile("andrew_file2")
	if err == nil { t.Error("andrew_file2 should not exist", err) }
}


func TestGetWrongPassword(t *testing.T) {
	userlib.SetDebugStatus(false)

	this_user, err1 := GetUser("alice", "foobar")
	if err1 == nil { // Test with wrong password
		// t.Error says the test fails
		t.Error("Failed to initialize user", this_user)
	}

	// t.Log() only produces output if you run with "go test -v"
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestStorage(t *testing.T) {
	// Get User Test
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	// t.Log("Loaded user", u)

	// Test StoreFile
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	// t.Log("File1 on store", v)

	v2, err2 := u.LoadFile("file1")
	// t.Log("File1 on load", v2)
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}

	// Tests AppendFile
	err9 := u.AppendFile("file1", []byte("a"))
	if err9 != nil {
		t.Error("Error in process of appending", err9)
	}
	v3, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to append and load", err3)
	}
	vt := []byte("This is a testa")
	if !reflect.DeepEqual(vt, v3) {
		t.Error("Appended file is not the same", vt, v3)
	}
}

func TestShare(t *testing.T) {
	// Test GetUser
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	// Test InitUser
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	// Test basic ShareFile functionality, Alice shares file1 with Bob (she calls it file2)
	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}


	// Test Bob shares file with Carol

	var v3 []byte
	var msgid string

	u3, err3 := InitUser("carol", "yolo")
	if err3 != nil {
		t.Error("Failed to initialize carol", err3)
	}
	
	msgid, err = u2.ShareFile("file2", "carol")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u3.ReceiveFile("file3", "bob", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	// Should all be the same
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file v is not the same", v, v3)
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file v2 is not the same", v2, v3)
	}

	// Alice revokes file
	err = u.RevokeFile("file1")
	if err != nil {
		t.Error("Error in process of revoking file", err)
	}

	file1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Alice was not able to access the file after revoking", err)
		t.Error("Here is file1", file1)
	}

	file1bob, err := u2.LoadFile("file2")
	if file1bob != nil {
		t.Error("Bob can access the file", file1bob)
	}

	file1carol, err := u3.LoadFile("file3")
	if file1carol != nil {
		t.Error("Carol can access the file", file1carol)
	}
}

func TestRevoke(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	
	u2, err2 := InitUser("hannah", "pw2")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	orig_data := []byte("Hi there Hannah")
	u1.StoreFile("file", orig_data)

	magic_string, err3 := u1.ShareFile("file", "hannah")
	if err3 != nil {
		t.Error("Failed to share the file", err3)
	}
	err3 = u2.ReceiveFile("alice_file", "alice", magic_string)
	if err3 != nil {
		t.Error("Failed to receive the share message", err3)
	}

	u1.RevokeFile("file")
	_, err4 := u1.LoadFile("file")
	if err4 != nil {
		t.Error("RevokeFile not working properly", err4)
	}

	_, err4 = u2.LoadFile("file")
	if err4 == nil {
		t.Error("RevokeFile not working properly", err4)
	}
	
	//new_file_data := []byte("Sorry there Hannah")
	//u1, _ := GetUser("alice", "pw1")
	//u1.StoreFile("file", new_file_data)
}
