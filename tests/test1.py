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
    config_parser = ConfigParser()
    config_file = open_config(config_filename)
    data_file = open_config(datafile_filename)
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
    for section_existing in config_parser.sections():
        if section == section_existing:
            print('Taken Already')
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
    hashed_password = config_parser.get(section, 'hashed_password')
    if md5_crypt.verify(password, hashed_password):
        print('Login Successful')
        return section
    else:
        print('Inavlid Credentials')


print(check_username('a', 'patient'))
print(check_username('a', 'patient'))
print(register('a', 'abc', 'patient'))
print(register('b', 'abc', 'patient'))
