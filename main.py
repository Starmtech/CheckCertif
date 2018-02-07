#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys, os
import ssl
import socket


def coloriage(s, color, bold=False):
   colors = {'red': 31, 'green': 32, 'yellow': 33,
             'blue': 34}
   if os.getenv('ANSI_COLORS_DISABLED') is None and color in colors:
       if bold:
           return '\033[1m\033[%dm%s\033[0m' % (colors[color], s)
       else:
           return '\033[%dm%s\033[0m' % (colors[color], s)
   else:
       return s

def checkCA(url, v=True):
   c = ssl.create_default_context()
   s = c.wrap_socket(socket.socket(), server_hostname=url)
   try:
      s.connect((url, 443))
      cert = s.getpeercert()
      value = dict(x[0] for x in cert['issuer'])
      by = value['commonName']
      date = value['notAfter']
      print date
      print by
      tab2 = {'Symantec Class 3 Secure Server CA - G4': False, 'Symantec Class 3 DSA SSL CA': False, 'Symantec Class 3 Secure Server SHA256 SSL CA': False, 'VeriSign Class 3 Secure Server CA - G3': False, 'VeriSign Class 3 International Server CA - G3': False, 'Symantec Class 3 Secure Server SHA256 SSL CA': False, 'thawte SSL CA - G2': False, 'GeoTrust SHA256 SSL CA': False, 'RapidSSL SHA256 CA - G3': False, 'RapidSSL SHA256 CA':False}
      v = tab2[by]
   except KeyError:
      v = True
   except socket.error:
        print 'Error: Connexion Refusée'
        by = 0
   return v, by

if __name__ == '__main__':
   if len(sys.argv) >= 2:
      url = sys.argv[1]
   else:
      url = raw_input('Veuillez indiquer une URL: ')
   cert, by = checkCA(url)
   if by != 0:
      print '----------------------------------------------------------'
      print 'domaine : ', url

      if cert == False:
         print by +':'+ coloriage(' Certificat Invalide', 'red', True)
      else:
         print by +':'+ coloriage(' Certificat Valide', 'green', False)
      print '----------------------------------------------------------'
