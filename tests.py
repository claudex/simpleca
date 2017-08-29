""" Unit tests  for simpleca """
#pylint: disable=protected-access
import unittest
import shutil
import os.path
import stat

from datetime import datetime, timedelta

from OpenSSL import crypto
import simpleca

class TemplateTestCase(unittest.TestCase):
    """ Generic template to factorize setuup/teardown """
    pass


class InitTestCase(TemplateTestCase):
    """ Test the CA initialization """
    def setUp(self):
        self.ca_dir = './catest'
        self.sca = simpleca.SimpleCA(self.ca_dir)
        self.sca._init_dir()
        self.sca._init_serial()

    def tearDown(self):
        shutil.rmtree(self.ca_dir)

    def check_dir(self, path, mode):
        """ Check generic ca dir """
        self.assertTrue(os.path.isdir(self.ca_dir + path))
        self.assertEqual(stat.S_IMODE(os.stat(self.ca_dir + path).st_mode),
                         mode)
    def test_root_dir_created(self):
        """ Check root ca dir """
        self.check_dir('', 0o755)
    def test_cert_dir_created(self):
        """ check cert ca dir """
        self.check_dir(simpleca.CERT_DIR_NAME, 0o755)
    def test_crl_dir_created(self):
        """ check crl ca dir """
        self.check_dir(simpleca.CRL_DIR_NAME, 0o755)
    def test_newcert_dir_created(self):
        """ check req ca dir """
        self.check_dir(simpleca.NEWCERT_DIR_NAME, 0o755)
    def test_private_dir_created(self):
        """ check private ca dir """
        self.check_dir(simpleca.PRIVATE_DIR_NAME, 0o700)
    def test_dont_override(self):
        """ check exception when dir exist """
        self.assertRaises(FileExistsError, self.sca.init_ca)
    def test_index_create(self):
        """ check the index is empty """
        self.assertTrue(os.path.isfile(self.ca_dir + simpleca.INDEX_NAME))
        self.assertEqual(os.path.getsize(self.ca_dir + simpleca.INDEX_NAME), 0)
    def test_serial_create(self):
        """ check the serial number """
        self.assertTrue(os.path.isfile(self.ca_dir + simpleca.SERIAL_NAME))
        with open(self.ca_dir + simpleca.SERIAL_NAME) as serial:
            serial_number = serial.read()
            self.assertEqual(serial_number, '1000')

class CaKeys(TemplateTestCase):
    """ Checks the key and cert for the CA """
    def setUp(self):
        self.ca_dir = './catest'
        self.sca = simpleca.SimpleCA(self.ca_dir)
        self.sca.key_bits = 512
        self.sca.init_ca()

    def tearDown(self):
        shutil.rmtree(self.ca_dir)

    def test_serial_create(self):
        """ check the serial is incremented """
        self.assertTrue(os.path.isfile(self.ca_dir + simpleca.SERIAL_NAME))
        with open(self.ca_dir + simpleca.SERIAL_NAME) as serial:
            serial_number = serial.read()
            self.assertEqual(serial_number, '1001')

    def test_privkey(self):
        """ check the privkey exists and is consistent """
        with open(self.ca_dir + simpleca.PRIVATE_DIR_NAME + '/ca.key') as private_file:
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_file.read())
            self.assertTrue(pkey.check())

    def test_ca_certificate(self):
        """ check if the certificate is auto signed """
        with open(self.ca_dir + simpleca.CERT_DIR_NAME + '/ca.crt') as cert_file:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                           cert_file.read())

        exp = cert.get_notAfter()
        ten_years = datetime.utcnow() + timedelta(30*365)

        self.assertEqual(exp.decode('ascii'), ten_years.strftime('%Y%m%d%H%M%SZ'))

    def test_ca_certificate_time(self):
        """ check if the certificate is valid enough time """
        with open(self.ca_dir + simpleca.CERT_DIR_NAME + '/ca.crt') as cert_file:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                           cert_file.read())
        store = crypto.X509Store()
        store.add_cert(cert)
        store_context = crypto.X509StoreContext(store, cert)
        store_context.verify_certificate()

    def test_new_certificate(self):
        """ check if the generated certificate is valid """
        self.sca.new_cert('test')
        with open(self.ca_dir + simpleca.CERT_DIR_NAME + '/test.crt') as cert_file:
            subject = cert_file.readline()
            issuer = cert_file.readline()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                           cert_file.read())
            self.assertEqual(subject, 'subject=/CN=test\n')
            self.assertEqual(issuer, 'issuer=/CN=ca\n')
        with open(self.ca_dir + simpleca.CERT_DIR_NAME + '/ca.crt') as ca_file:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                              ca_file.read())
        store = crypto.X509Store()
        store.add_cert(ca_cert)
        store_context = crypto.X509StoreContext(store, cert)
        store_context.verify_certificate()


    def test_new_certificate_time(self):
        """ check if the certificate is valid enough time """
        self.sca.new_cert('test')
        with open(self.ca_dir + simpleca.CERT_DIR_NAME + '/test.crt') as cert_file:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                           cert_file.read())
        exp = cert.get_notAfter()
        one_year = datetime.utcnow() + timedelta(365)

        self.assertEqual(exp.decode('ascii'), one_year.strftime('%Y%m%d%H%M%SZ'))


#class PrettyPrint(unittest.TestCase)

if __name__ == '__main__':
    unittest.main()
