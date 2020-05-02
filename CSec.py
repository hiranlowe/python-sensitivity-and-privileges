from configparser import ConfigParser
import getpass
from passlib.hash import md5_crypt

func = 1

config_filename = 'config.ini'
datafile_filename = 'data.ini'

config_parser = ConfigParser()


def open_config(config_filename):
    config_file = open(config_filename, 'a')
    return config_file


def register(username, hashed_password, user_type):
    config_file = open_config(config_filename)
    data_file = open_config(datafile_filename)
    config_parser = ConfigParser()

    if user_type == 'staff':
        if username.split('@')[-1] == 'reception':
            # can read peronal and sickness and write none,personal of himself
            privilege_level = 1
        elif username.split('@')[-1] == 'pharmacy':
            # can access peronal, sickness, drugs,personal of himself
            privilege_level = 2
        elif username.split('@')[-1] == 'lab':
            # can read peronal, sickness, reports and write reports,personal of himself
            privilege_level = 3
        elif username.split('@')[-1] == 'nurse':
            # can read peronal, sickness, drugs, reports and write personal of himself
            privilege_level = 4
        elif username.split('@')[-1] == 'doc':
            # can read peronal, sickness, drugs, reports and write sickness, drugs,personal of himself
            privilege_level = 5

    elif user_type == 'patient':
        # can read peronal, sickness, drugs, reports and write personal of himself
        privilege_level = 0

    config_parser['User'+' ' + username.split('@')[0]] = {'username': username,
                                                          'hashed_password': hashed_password,
                                                          'user_type': user_type,
                                                          'privilege_level': privilege_level}
    config_parser.write(config_file)
    config_file.close()

    config_parser['User'+' ' + username.split('@')[0]] = {'personal_details': '',
                                                          'sickness_details': '',
                                                          'drug_prescription': '',
                                                          'lab_test_prescription': ''}

    config_parser.write(data_file)
    data_file.close()
    print('Registration Successfull')

    return True


def check_username(username, user_type):
    if username == '':
        print('Invalid Username')
        return True
    config_parser.read(config_filename)
    section = 'User' + ' ' + username.split('@')[0]
    print(section)
    if section in config_parser.sections():
        print('Records Found')
        return True
    else:
        return False

    if user_type == 'staff':
        if username.split('@')[-1] in ['doc', 'nurse', 'lab', 'pharmacy', 'reception']:
            return False
        else:
            print('Invalid Username')
            return True


def login(username, password):
    config_parser.read(config_filename)
    section = 'User' + ' ' + username.split('@')[0]
    if section in config_parser.sections():
        hashed_password = config_parser.get(section, 'hashed_password')
        if md5_crypt.verify(password, hashed_password):
            print('Login Successful')
            return section
        else:
            print('Inavlid Credentials')
    else:
        print('No Records Found')


def patient_details(current_user):
    if current_user == None:
        print('You should login to continue')
        return False
    data_file = open_config(datafile_filename)
    config_parser = ConfigParser()
    config_parser.read(config_filename)
    privilege_level = config_parser.get(current_user, 'privilege_level')
    print(privilege_level)
    current_username = config_parser.get(current_user, 'username')
    personal_details = ''
    sickness_details = ''
    drug_prescription = ''
    lab_test_prescription = ''

    while True:
        print('Enter the username of the patient: ', end='')
        patient_username = input().strip().split('@')[0]
        print('patient_username')
        if check_username(patient_username, 0):
            user = 'User' + ' ' + patient_username.split('@')[0]
            username = config_parser.get(user, 'username')
            break
        else:
            print('No Records')

    config_parser = ConfigParser()
    config_parser.read(datafile_filename)
    print('Enter the section you want(personal, sickness, drugs, lab): ', end='')
    section = input().strip()
    print('Enter the process you want(read, write): ', end='')
    process = input().strip()

    if section == 'personal':
        if process == 'write':
            if username == current_username:
                print('Enter details: ')
                personal_details_old = config_parser.get(
                    user, 'personal_details')
                personal_details = input().strip()
                personal_details = personal_details_old + ', ' + personal_details
                config_parser.set(user, 'personal_details', personal_details)
                print(config_parser.get(user, 'personal_details'))
                print('Updated Successfully')
            else:
                print('You do not have permission to do this')
        if process == 'read':
            print('here')
            if username == current_username or privilege_level == '1' or privilege_level == '2' or privilege_level == '3' or privilege_level == '4' or privilege_level == '5':
                personal_details = config_parser.get(user, 'personal_details')
                print(personal_details)
            else:
                print('You do not have permission')

    elif section == 'sickness':
        if process == 'write':
            if privilege_level == '5':
                print('Enter details: ')
                sickness_details_old = config_parser.get(
                    user, 'personal_details')
                sickness_details = input().strip()
                sickness_details = sickness_details_old + ', ' + sickness_details
                config_parser.set(user, 'sickness_details', sickness_details)
                print(config_parser.get(user, 'sickness_details'))
                print('Updated Successfully')

        elif process == 'read':
            if username == current_username or privilege_level == '1' or privilege_level == '2' or privilege_level == '3' or privilege_level == '4' or privilege_level == '5':
                sickness_details = config_parser.get(user, 'sickness_details')
                print(sickness_details)
            else:
                print('You do not have permission')
    elif section == 'drugs':
        if process == 'write':
            if privilege_level == 5:
                print('Enter details: ')
                drug_prescription_old = config_parser.get(
                    user, 'personal_details')
                drug_prescription = input().strip()
                drug_prescription = drug_prescription_old + ', ' + drug_prescription
                config_parser.set(user, 'drug_prescription', drug_prescription)
                print(config_parser.get(user, 'drug_prescription'))
                print('Updated Successfully')
            else:
                print('you do not have permission')

        elif process == 'read':
            drug_prescription = config_parser.get(user, 'drug_prescription')
            if username == current_username or privilege_level == '5' or privilege_level == '4' or privilege_level == '2':
                print(drug_prescription)
            else:
                print('you do not have permission')

    elif section == 'lab':
        if process == 'write':
            if privilege_level == 3:
                print('Enter details: ')
                lab_test_prescription_old = config_parser.get(
                    user, 'personal_details')
                lab_test_prescription = input().strip()
                lab_test_prescription = lab_test_prescription_old + ', ' + lab_test_prescription
                config_parser.set(
                    user, 'lab_test_prescription', lab_test_prescription)
                print(config_parser.get(user, 'lab_test_prescription'))
                print('Updated Successfully')
            else:
                print('you do not have permission')
        elif process == 'read':
            lab_test_prescription = config_parser.get(
                user, 'lab_test_prescription')
            if username == current_username or privilege_level == '5' or privilege_level == '4' or privilege_level == '3':
                print(lab_test_prescription)

            else:
                print('you do not have permission')
    else:
        return False

    config_parser.write(open('data.ini', 'w'))
    data_file.close()
    return True


while (func != 0):
    print("function (register, login, details or 0) :")
    func = input().strip()
    if func == "register":
        print('/***********User Registration*********/')

        print('username(): ', end='')
        username = input().strip()
        password = ''
        confirm_password = 'aa'
        user_type = 'none'
        user = ''
        while True:
            if check_username(username, user_type):
                print('username: ', end='')
                username = input().strip()
            else:
                break
        password = getpass.getpass(prompt='password')
        confirm_password = getpass.getpass(prompt='confirm_password')
        while True:
            if password != confirm_password:
                password = getpass.getpass(prompt='password')
                confirm_password = getpass.getpass(prompt='confirm_password')
                print('Not matching')
            else:
                break
        hashed_password = md5_crypt.hash(password)
        print('user_type (staff or patient): ', end='')
        user_type = input().strip()
        if user_type == 'staff':

            while True:
                print(
                    'staff username(username@doc|nurse|lab|pharmacy|reception): ', end='')
                username = input().strip()
                if check_username(username, user_type):
                    continue
                else:
                    break
        register(username, hashed_password, user_type)
        print('/***********User Login*********/')
        user = login(username, password)
        print('/***********Patient Details*********/')

        patient_details(user)

    if func == "login":
        print('/***********User Login*********/')

        print('username: ', end='')
        username = input().strip()

        password = getpass.getpass(prompt='password')

        user = login(username, password)
        print('/***********Patient Details*********/')

        patient_details(user)

    if func == "details":
        print('/***********Patient Details*********/')
        privilege_level = login

        patient_details(user)

    if func == 0:
        print('Bye')
        break
