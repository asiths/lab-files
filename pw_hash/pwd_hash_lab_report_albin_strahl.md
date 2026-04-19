# This is the lab report for mandatory lab pwd_hash.

# The objective of this lab was the implementation of hashing functionality within a provided web application, specifically:

- Replacing the plaintext password stored in the server_password.txt file (Tuff3-Uff3) with a hashed variant.
- Implementing hashing of the plaintext received from the client when requesting the header [X-Secret-Password].

I accomplished the first of these two steps by hashing the provided plaintext password (Tuff3-Uff3), using the sha3-384 algorithm as instructed. Specifically, I used the program "thash" [github.com/TheQuantumPhysicist/thash], running the following command:

echo -n "Tuff3-Uff3" | thash -a sha3-384 > /path/to/server_password.txt

# Thash has been a really neat find, it supports a bunch of algorithms (-a flag), different output formats (-F flag), can grab input from stdin via pipe or from file (-f [/path/to/file] flag) and supports recursive hashing within a single command (-i [integer_amount_of_iterations] flag).

Thash computed the following hexdigest:

42def70f6860518de54c54769aa03ab6b58cf02c0afb3fac03af04aa5604bd617cdf7141cc336b07529a2741650d3d61

This hexdigest was then placed into the file 'server_password.txt', replacing the original plaintext password. With the password replaced, the web server code now had to be modified to hash the incoming password in the same way. Additional requirements for the "meritorious" grade were to implement password salting and additional rounds of hashing, and I decided to build towards that goal from the beginning.

My solution was the implementation of two separate functions, 'hash_password()' and 'verify_password()', shown below:

hash_password()

def hash_password(plaintextpassword: str, iterations: int = 100000) -> bytes:
    salt = os.urandom(32)
    digest = sha3384(salt + plaintextpassword.encode()).digest()
    for x in range(iterations):
        digest = sha3384(digest).digest()
    return salt + digest

This function takes the parameter "plaintextpassword" as input, generates a random salt and hashes the combination of the salt and the byte-encoded plaintext pw, storing it in the variable "digest". It then proceeds to apply the same hashing algorithm an additional 100000 times for good measure, and finally returns a combined byte value including the original salt and the final digest.

verify_password()

def verify_password(plaintextpassword: str, hashedpassword: bytes, iterations: int = 100000) -> bool:
    salt = hashedpassword[:32]
    digest = hashedpassword[32:]
    test_digest = sha3384(salt + plaintextpassword.encode()).digest()
    for x in range(iterations):
        test_digest = sha3384(test_digest).digest()
    # Compare the computed hashes using imported hmac function to avoid timing attacks
    return compare_hashes(digest, test_digest)

The verification function works by accepting two input parameters, "plaintextpassword" and "hashedpassword". The former parameter will take the value received from the header as input, and the new "hashedpassword" parameter takes the byte value (salt+digest) returned by the hash_password() function. It then splits the received value into two variables, salt and digest, where 'salt' is the original salt provided by the os.urandom(32) function and 'digest' is the **final** digest outputted by the hash_password() function. It then creates a new variable for later comparison, 'test_digest', which is computed the exact same way as when the hash_password() function calculates its final digest - this is achieved by reusing the same salt and input "plaintextpassword" parameter.

# "Salting" the password has a few important benefits for security, and while the scope of this lab does not showcase the true strength of salting (containing only a single salt), it is a very useful technique to know. For example, salting your hash computations makes "rainbow table" attacks very difficult, since an attacker now has to provide such a table for *every single possible salt value* which in the case of a 32-byte salt (such as the one I used) would mean calculating up to a total of 256^32 rainbow tables. While it is unlikely that the correct table would be the last one to be calculated, the sheer size of the set of all possible tables makes the prospect of calculating any significant portion laughable. 

# Furthermore, systems with multiple users may find that those users do not always choose unique passwords - without salting, this creates a huge issue since every overlapping password also means an overlapping hash, but with salting properly implemented the chance of a collision is reduced to about 1/number-of-bytes^32, realistically only causing a collision if two randomly generated salts happen to end up with the same value, assigned to two separate users with the same password. (in reality this chance is probably slightly higher, since it is theoretically possible for two different salts to produce the same result when paired with the same password - however, the insanely low chance of this happening coupled with the fact that a competent sysadmin would probably implement checks which prevent the storage of identical hashes in the first place).

Once the test_digest variable has been calculated, the function returns true/false dependent on the result of the function 'compare_hashes(digest, test_digest)'.

# This is an imported function from the hmac library (specifically hmac.compare_digest, aliased as compare_hashes) which provides an important advantage over using a simple == comparison; while the == operation will fail as soon as a single byte mismatch is encountered, the hmac function is designed specifically to always take the same amount of time when evaluating, regardless of **when** a mismatched byte is encountered. This prevents so called "timing attacks", where an attacker could send a bunch of requests with slight variations and analyze the "time-to-fail" for each request, which would eventually start revealing the byte structure of the password hash if left unchecked as the ttf increases.

# Timing attacks would not necessarily be a huge vulnerability in this case, as the time taken up by the hashing portion is orders of magnitude greater than the time a == comparison would take, making it extremely difficult to discern actual patterns from random noise when analyzing ttf variation. However, extremely difficult =/= impossible.

Now that I had defined the required functions, the next step was to implement their usage within the server.py code, which I did according to the following steps:

Firstly, define the functions within the code. (Lines 55-70)

Secondly, call the hash_password function like this:

    password = hash_password(password)
(Line 73)

# The variable 'password' initially stores the password obtained from the txt file (in actuality the first hash of the actual plaintext password); this value is then updated to be the aforementioned **final** digest, after a total of 100000+1 hashing rounds (+1 since the stored password is already hashed once).

Thirdly, within the get_gift_advice() function, immediately after the 'request_password' variable is initially obtained by:

    'request_password = request.headers['X-Secret-Password']',
(Line 108)

Replace the initial plaintext value of 'request_password' with the first hash of itself, ensuring that 'request_password' now matches what is stored in server_password.txt:

    request_password = sha3384(request_password.encode()).hexdigest()
(Line 110)

Finally, call the verify_password function, taking the variable 'request_password' as input for the parameter 'plaintextpassword' (now technically a misnomer :P), and the variable 'password' as input for the parameter 'hashedpassword':

    if verify_password(request_password, password):
        log.info('Successfully authenticated request - returning gift advice!')
        return generate_gift_advice()
    else:
        log.warning('Got request with header "X-Secret-Password" not matching the server password')
        log.debug(f'Value of request header "X-Secret-Password" was "{request_password}"')
        abort(401)
(Lines 113-119)

This concludes the demonstration of my hashing implementation, but I would like to round off this report by talking a little bit about the weaknesses of using iterative hashing vs a dedicated KDF:

While researching concepts for this lab, I discovered that iterative sha3-384 hashing is not a great choice for a production deployment - the issue stems from the fact that attacks against this type of hashing are cheap to scale: Due to the sha3-384 algorithm having a very small memory footprint, attacks against it can easily be scaled horizontally given access to sufficiently powerful hardware. 

For example, an attacker with access to a moderately expensive GPU or a dedicated ASIC-chip setup purpose-built to compute hashes (similarly to how a dedicated cryptocurrency miner works), could easily run millions or even billions of parallel operations **per second** against this type of encryption. A better choice for the "real world" would be a purpose-built KDF such as bcrypt/scrypt/Argon2 or similar. Designed to be slow by nature, as well as expensive to scale attacks against due to their much larger memory footprint, KDFs such as these provide much better hardening in a real production deployment.

Thank you for reading, and have a nice day :D