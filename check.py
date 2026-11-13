import sha256

#fpi = file_path_input
fpi = input("Enter the path to your password file: ")
#fp = file_path
fp = fpi.strip()
#ih = input_hash
ih = input("Enter the password: ")

def hasher(fp):
    if fp.endswith(".txt") == False:
        return "please give a .txt file"

    passwords = []
    with open(fp, 'r') as file:
        for line in file:
            passwords.append(line.strip())

    ph = []
    for a in passwords:
        #ph = passwords_hashed
        ph.append(sha256.sha256(a.encode()))

    return ph, passwords


def checker(ph, ih, passwords):
    for a in ph:
        if ih == a:
            answer = passwords[ph.index(a)]
            return answer

ph, passwords = hasher(fp)

print(checker(ph, ih, passwords))