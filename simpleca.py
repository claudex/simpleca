#!/usr/bin/env python3
"""
SimpleCA is a tool to easily manage a Certificate autority
"""

import fcntl
import os
from datetime import datetime, timedelta

import click
from OpenSSL import crypto
from OpenSSL.crypto import PKey, X509

CERT_DIR_NAME = '/certs'
CRL_DIR_NAME = '/crl'
NEWCERT_DIR_NAME = '/newcerts'
PRIVATE_DIR_NAME = '/private'
INDEX_NAME = '/index.txt'
SERIAL_NAME = '/serial'
CA_PRIVKEY_NAME = PRIVATE_DIR_NAME + '/ca.key'

class SimpleCA:
    """ class handling the CA operations """

    def __init__(self, ca_dir):
        """

        Keyword arguments:
        ca_dir -- the directory where the CA files will be stored
        """
        self.ca_dir = ca_dir
        self.subject = 'Simple CA'
        self.commonname = 'ca'
        self.key_bits = 4096

    def init_ca(self):
        """ Create the CA directories, initiliaze the files """
        self._init_dir()
        self._init_serial()
        self._init_keys()

    def new_cert(self, commonname, extensions=None):
        """ Create a new signed certificate

        Keyword arguement:
        commonname -- the certificate subject common name
        """
        pkey = self._create_pkey(commonname)
        self._create_cert(pkey, commonname, extensions)

    def _get_serial(self):
        """ Get the current serial and increment the serial file """
        with open(self.ca_dir + SERIAL_NAME, 'r+') as serial_file:
            fcntl.flock(serial_file, fcntl.LOCK_EX)
            serial = int(serial_file.read())
            serial_file.seek(0)
            serial_file.truncate()
            serial_file.writelines(['%d'% (serial + 1)])
        return serial

    def _get_cert_path(self, cert_name):
        """ Get the path where the certificates are stored """
        return self.ca_dir + CERT_DIR_NAME + '/' + cert_name + '.crt'

    def _get_key_path(self, key_name):
        """ Get the path where the private keys are stored """
        return self.ca_dir + PRIVATE_DIR_NAME + '/' + key_name + '.key'

    def _create_pkey(self, commonname):
        """ Generate a key pair and store it in the private key directory

        The key file will be named from the common name
        """
        pkey = PKey()
        pkey.generate_key(crypto.TYPE_RSA, self.key_bits)
        private = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                         pkey).decode()
        key_path = self._get_key_path(commonname)
        if os.path.exists(key_path):
            raise FileExistsError(key_path)
        with open(key_path, 'w') as private_file:
            private_file.writelines(private)

        return pkey

    def _create_cert(self, pkey, commonname, extensions, **kwargs):
        """ Create a certificate

        Arguments:
        pkey -- the key pair for the certificate
        commonname -- the common name for the certificate subject
        extensions -- the X509Ext list

        Keywords arguments:
        expire -- the number for days the certificate is valid (default 365)
        version -- the version number for the certificate (default 1)
        """

        expire_kw = 'expire'
        if expire_kw in kwargs:
            expire = kwargs[expire_kw]
        else:
            expire = 365

        version_kw = 'version'
        if version_kw in kwargs:
            version = kwargs[version_kw]
        else:
            version = 1

        now = datetime.utcnow()
        cert = X509()
        cert.get_subject().CN = commonname
        cert.get_issuer().CN = self.commonname
        startdate = now.strftime('%Y%m%d%H%M%SZ')
        cert.set_notBefore(startdate.encode('ascii'))
        enddate = (now+timedelta(expire)).strftime('%Y%m%d%H%M%SZ')
        cert.set_notAfter(enddate.encode('ascii'))
        cert.set_pubkey(pkey)
        cert.set_serial_number(self._get_serial())
        cert.set_version(version)

        if extensions:
            cert.add_extensions(extensions)

        self._sign_cert(cert)

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM,
                                           cert).decode()
        with open(self._get_cert_path(commonname), 'w') as cert_file:
            cert_file.writelines(get_pretty_subject(cert))
            cert_file.writelines(cert_pem)

        return cert

    def _sign_cert(self, cert):
        """ Sign the certificate with the given key """
        with open(self._get_key_path(self.commonname), 'r') as private_file:
            data = private_file.read()
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                          data)
        cert.sign(pkey, 'sha256')


    def _init_dir(self):
        """ Create the directory structure for the CA"""
        for directory in ['', CERT_DIR_NAME, CRL_DIR_NAME, NEWCERT_DIR_NAME,
                          PRIVATE_DIR_NAME]:
            mode = 0o755 if directory != PRIVATE_DIR_NAME else 0o700
            os.mkdir(self.ca_dir + directory, mode=mode)

    def _init_serial(self):
        """ Initialize the serial for cert id """
        index_name = self.ca_dir + '/index.txt'
        serial_name = self.ca_dir + '/serial'
        with open(index_name, 'w'):
            pass
        with open(serial_name, 'w') as serial:
            serial.writelines(['1000'])

    def _init_keys(self):
        """ Generate the root CA key pair """

        basic_constraints = crypto.X509Extension('basicConstraints'.encode('ascii'), True,
                                                 'CA:TRUE, pathlen:0'.encode('ascii'))
        pkey = self._create_pkey(self.commonname)
        self._create_cert(pkey, self.commonname, [basic_constraints], expire=30*365)

def _get_pretty_name(name):
    """ Get a pretty string from a X509Name """
    pretty = ''
    if name.countryName:
        pretty += '/C=' + name.countryName
    if name.stateOrProvinceName:
        pretty += '/ST=' + name.stateOrProvinceName
    if name.localityName:
        pretty += '/L=' + name.localityName
    if name.organizationName:
        pretty += '/O=' + name.organizationName
    if name.organizationalUnitName:
        pretty += '/OU=' + name.organizationalUnitName
    if name.commonName:
        pretty += '/CN=' + name.commonName
    if name.emailAddress:
        pretty += '/email=' + name.emailAddress
    return pretty


def get_pretty_subject(cert):
    """ Get a pretty string with the subject and the issuer of a cert """
    subject = 'subject=' + _get_pretty_name(cert.get_subject())
    issuer = 'issuer=' + _get_pretty_name(cert.get_issuer())
    return subject + '\n' + issuer + '\n'



@click.group()
def cli():
    """Entrypoint for the programm"""
    pass

@click.command()
@click.option('--ca-dir', default='./ca',
              help='directory where the CA will be stored')
def initca(ca_dir):
    """ Initialize the CA directory
    This will create the inital files, including the CA key pair"""
    click.echo('Initiliasing new CA in %s' % ca_dir)
    sca = SimpleCA(ca_dir)
    try:
        sca.init_ca()
    except FileExistsError as err:
        click.echo('The CA directory (%s) exists, not doing anything' %
                   err.filename)
        exit(1)

@click.command()
@click.option('--ca-dir', default='./ca',
              help='directory where the CA is stored')
@click.argument('commonname')
def create_cert(commonname, ca_dir):
    """ Create a certificate with the specified COMMONNAME """
    sca = SimpleCA(ca_dir)
    sca.new_cert(commonname)

cli.add_command(initca)
cli.add_command(create_cert)

if __name__ == '__main__':
    cli()
