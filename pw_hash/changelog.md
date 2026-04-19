The changes in this resubmission are:

Added salt file "saltis.txt":
    "definitely_a_good_random_salt"

Changed contents of "server_password.txt":

    "09e80f8b51c99145ce22c81018648cc8eab7417034286eea9d74636fda678644fa8d4fa515a5a43ef3823e427198bd88"
    This is prehashed (x100000) with the salt from salt file using command:

        cat plainpwsalt | sha3384 -i 99999 -F binary | sha3384

        # Plainpw is a test file containing plaintext pw + salt strings
        "Tuff3-Uff3definitely_a_good_random_salt"

Rewrote the server.py code:

    - Removed "hash_password()" function since stored password is prehashed.
    
    - Rewrote verify function to grab salt value from saltis.txt