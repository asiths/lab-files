# This is the lab report for mandatory lab pwd_crack

# The objectives of this lab were:

### Mandatory ("G")
- Obtain a copy of the "RockYou" password list (MD5 hash: 9076652d8ae75ce713e23ab09e10d9ee)
- Determine which hash types are used to store passwords in the file "shadow.bak"
- Use JtR ("john.sh") and the password list to crack Oscar's password
- Crack Bob's password by extending/permutating the password list (ends with =2022= or =2023=)

### Meritorious ("VG")
Use the "rules" functionality in "John The Ripper" _or_ create a custom script to extend/permutate
the "RockYou" wordlist for cracking the "root" user's password, based on the following information:
- System security requirements specify that the password must be at least 12 characters long
- Typically begins with a digit
- Typically ends with a dot (".") or the plus ("+") character

First, I had to obtain the "RockYou" password list - this was taken care of through a google search, at which point I found: https://weakpass.com/wordlists/rockyou.txt - this website advertised a list named "rockyou.txt" with the MD5 hash of 9076652d8ae75ce713e23ab09e10d9ee, which I proceeded to verify post-download using the ever so faithful thash:
    thash -a MD5 -f /path/to/rockyou.txt -> 9076652d8ae75ce713e23ab09e10d9ee

Now that the wordlist was secured, I had to identify which types of hashes were stored in shadow.bak. For this I used an online tool provided by the aptly named website "hashes.com" at the link https://hashes.com/en/tools/hash_identifier. This gave me the following result:

    $1$yG0gxZm8$PGFsqFnBE8uYMwyV3LHCA0 (root) - md5crypt
    $5$l4nu1mJdQ0DnGN/d$kxwjjvqLPz0ZOy88SoDNXRR1E.3oKDgWr.47kQpnAG2 (bob) - sha256crypt
    $6$3VNkreGOf5ORys4H$4/WhvPT0tMVY3qDe/HuF53p87OmaoXcWuxj57spEw1xQoWVYP0FmqUNS5ap0ctw9klnpZ5CADp4PhXeWy1LI1. (oscar) - sha512crypt

After a bit of extra searching sparked by the fact that all of the hashes seemed to begin with "$NUMBER$", I found some additional information:

$ is used as a delimiter, separating different fields.

The first section (between the first two "$"-signs) specifies the hash type, right in the string! - 1 is md5crypt, 5 is sha256crypt and 6 is sha512crypt.

The salt value used to generate the hash is also stored in this string, specifically in the second section. The salt values for each hash are:

Oscar: 3VNkreGOf5ORys4H
Bob: l4nu1mJdQ0DnGN/d
root: yG0gxZm8

# Additionally, I also found that the amount of "rounds" used by -crypt algorithms is also specified in the string if it deviates from the default (5000); since no rounds field is present, the default is assumed.

# Extracting the salt values doesn't help JtR work faster to my knowledge, since it already is perfectly capable of doing this on its own. However, it is useful to know when doing post-run verification.

With the wordlist and hash types in hand, I was now almost prepared to get cracking - the penultimate step was to create a file with the collected hashes "hashes.txt", followed by placing the two files "rockyou.txt" and "hashes.txt" in my /path/to/resources/labs/pwd_crack folder so jtr could access them.

Starting with Oscar's password:

    - From inside the vagrant lab box (at /home/vagrant/pwd):
        Command: ./john.sh --wordlist=rockyou.txt hashes.txt

# It was at this point I discovered that jtr was being very nice, opting to automatically select the correct hash type (presumably) based on the first line of "hashes.txt" (Oscar's password, sha512crypt) and also (!!) informing me that additional hash types (md5crypt and sha256crypt) were also found in the supplied "hashes.txt".

    The program ran for approximately 0 seconds (way to go, John!), and returned "mommy123" (really, Oscar?). To verify this, I did the following:
        Command: openssl passwd -6 -salt 3VNkreGOf5ORys4H "mommy123"

        This invokes openssl's password hashing functionality, using algorithm number 6 ($6$ - sha512crypt) and the salt value "3VNkreGOf5ORys4H" to hash the password "mommy123" - the output of this command was the following (sections separated with a space for readability):

        $6 $3VNkreGOf5ORys4H $4/WhvPT0tMVY3qDe/HuF53p87OmaoXcWuxj57spEw1xQoWVYP0FmqUNS5ap0ctw9klnpZ5CADp4PhXeWy1LI1.

        As we can see, the password "mommy123", when computed through the sha512crypt algorithm, indeed hashes to "4/WhvPT0tMVY3qDe/HuF53p87OmaoXcWuxj57spEw1xQoWVYP0FmqUNS5ap0ctw9klnpZ5CADp4PhXeWy1LI1." which proves that this is indeed the password used.

One down, two to go!

Next up, Bob's password:

    To crack this password, some modifications needed to be made; in the documentation for this lab, it was specified that Bob's password would end with either "=2022=" or "=2023=" - meaning we had to append these strings to all password candidates.

    To accomplish this, I added the following two lines to john.conf under [List.Rules:Wordlist]:
        
        Az"=2022="
        Az"=2023="
    
    These lines tells john to append (A) to the end of line (z) the strings "=2022=" and "=2023=".

    Running jtr with these rules [./john.sh --wordlist=rockyou.txt --format=sha256crypt --rules hashes.txt] yielded a result in about 10 seconds - "fullmoon=2022="

    Verifying with [openssl passwd -5 -salt l4nu1mJdQ0DnGN/d "fullmoon=2022="]:

        $5 $l4nu1mJdQ0DnGN/d $kxwjjvqLPz0ZOy88SoDNXRR1E.3oKDgWr.47kQpnAG2
        
        Bingo!

For the final challenge, cracking the root password's md5crypt hash, the instructions were as follows:

The root password would be at least 12 characters long, begin with a digit, and end with either "+" or "." - these requirements were more restrictive than for bob, which on one hand meant that the rules would have to be a bit more complex, but on the other hand also meant that a large number of the entries in "rockyou.txt" could be rejected outright; namely, candidates that were shorter than 10 characters could safely be disregarded:
    
    A 10 character "base" password is the minimum required to create a 12 character password when prepending a digit and appending either . or +.

With this in mind, to reduce the workload for jtr, I created a new wordlist "rockyou10ormore.txt" with the following command:

    awk 'length($0) >= 10' rockyou.txt > rockyou10ormore.txt

This new list consists of all entries in the original rockyou.txt which are 10 or more characters in length.


Following creation of the new wordlist, I added the complementary rules to john.conf:

    Az"\+"A0"[0-9]" - Append + and prepend digits 0-9
    Az"\."A0"[0-9]" - Append . and prepend digits 0-9

# Another way to achieve the same result using only the rules in john.conf could be to add a "reject" rule to both of these:
#   >9Az"\+"A0"[0-9]"
#   >9Az"\."A0"[0-9]"
# The >9 added here tells john to reject all candidates which are not **more than** 9 characters in length, AKA 10 or more.

Finally, I ran the command [./john.sh --wordlist=rockyou10ormore.txt --format=md5crypt --rules hashes.txt], and after ~10 minutes of waiting I was presented with:

    2winniethephoo.

Verifying with [openssl passwd -1 -salt yG0gxZm8 "2winniethephoo."]:

    $1 $yG0gxZm8 $PGFsqFnBE8uYMwyV3LHCA0

    Bingo (again)!

# Rounding off this report, I would like to present the section "How2CrackPasswordsFast" or "Why on earth do so many of you just add an exclamation mark and call it a day" or "Seriously, its really easy to make permutations of a wordlist" or "It says a MINIMUM of one special character" - This section will go into a few approaches one can take to (potentially) reduce the time cost of a password cracking attempt:

"How do I crack passwords faster?" - Unspecified JTR user after running incremental mode for three weeks.

This is a question which can't be answered fully in this document (or frankly any document, hooray for open ended questions!), but I will attempt to outline some concepts which may be helpful for the intrepid crackers among us:

In my estimation, the most important thing to keep in mind is that humans are, by their very nature, as prone to pattern repetition as they are prone to breathing; if I for example asked you, the reader, to make the password "VeryGoodPassword" more secure by adding a minimum of: 
    
    1. one numerical digit and 
    2. one "special" character (!"#¤%... and so on) 

What would the result be?

Would it be something like "VeryGoodPassword1!"? Maybe "Very1Good2Password3!?"? Or even "!Very?Good!Password123!"? It's very hard to say for sure which one of these closest resembled what your mind may have come up with, but what I can say (with a good deal of confidence) is that "Ve11234ry91002!¤!==/!G00ood!Passw+++ord9109" was *not* what you came up with - when presented with open ended requirements (or really any challenge if we're being honest), we are all prone to taking the path of least resistance if we do not actively work to counteract this instinct. 

This is not an indictment of human behavior, but a reflection of some very basic aspects of it - We generally like a process which involves as little friction as possible, we generally dislike processes which involve a lot of friction, we like when things work and we dislike when they dont. In the case of passwords, this tendency towards low-friction behavior is extremely consequential: Consider the earlier example where I asked you to make "VeryGoodPassword" more secure through adding non-letter characters, but now from the perspective of someone trying to guess it - in this situation, the tendency which serves to make the password owner's life easier now becomes an exploitable weakness. As the password cracker, you can leverage the knowledge that people are unlikely to overcomplicate things to dramatically reduce the set of possible candidates.

For an even better example, lets say you are trying to crack a password based on the following guidelines:

1. The password is at least 8 and at most 24 characters long.
2. The password contains at least one number, one special character and one uppercase letter.
3. The password's owner is known to you, as is their undying love for all things related to Star Wars.

You could approach this by attempting to systematically work through every possible combination that satisfies the technical requirements:

Aa!0000
Aa!0001
Aa!0002
...

Or maybe

!0000aA
!0000aB
...

It quickly becomes apparent that this won't be likely to yield a match anytime soon - the set of possible combinations is simply too large for a human to feasibly exhaust within a reasonable time frame. Of course, us modern folk have access to a range of fancy machinery which can work faster (by several orders of magnitude), but even the flashiest FPGA setup will eventually meet its match in an arms race against exponential growth. 

# A theoretical maximum calculable set (if you had the power to utilize the sum energy of the entire observable universe towards this singular purpose) I found was 327 bits of entropy (2^327 combinations, ~10^98 in base 10) - this equation will no doubt change in the future with the increasing capability of quantum computing, but the fact that it is still a VERY large set remains.

So, what do we do if we can't expect to be able to systematically exhaust every combination by just working really hard at it? We work smarter, of course! - Instead of testing every combination of random data, we *prune* our working set by applying rules, for example:

1. The password likely contains a word which can be found in a dictionary, or some permutation of it (h3ll0 instead of hello, for example)
2. The word(s) which can be found in the password are more likely than random chance to be related to Star Wars.
3. The addition of numbers and special characters can initially be assumed to have been kept to a minimum.

Using these three very basic rules, we can throw out the vast majority of possible combinations before we even begin our attempt; this technique gets more powerful the more information you have about the person behind the password, allowing you to fine tune your pruning with ever greater degrees of accuracy.

In summary, the answer to "how to crack passwords faster" is as open ended as the question; it depends, like so many other things, on what kind of and how much information is available to you at any given time.

That concludes this report, thank you for reading (and for the fun excercise!) and have a great [applicable time of day]!