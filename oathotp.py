#    Copyright (C) 2009 Geoff Hoff, http://github.com/ghoff
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#    or download it from http://www.gnu.org/licenses/gpl.txt

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app
import os
import hotpy
import binascii
import string

class HotpData(db.Model):
  id = db.StringProperty(required=True)
  serialno = db.StringProperty(required=True)
  iv = db.StringProperty(required=True)
  seed = db.StringProperty(required=True)
  sequence = db.IntegerProperty(required=True)
  otpdigits = db.IntegerProperty(required=True)

def calc_otp(request):
  success = 0
  allowed = string.ascii_letters + string.digits + "-_"
  delete_table = string.maketrans(allowed, ' ' * len(allowed))
  table = string.maketrans('', '')
  id = str(request.get('id'))
  #strip all but ascii letters, numbers, dash and underscore
  id = id.translate(table, delete_table)
  querys = HotpData.all()
  querys.filter('id =', id)
  if querys.count() >= 1:
    for query in querys:
      hconfig = dict()
      #extract pin from full pin+otp
      tmppin = str(request.get('pin'))
      tmppin = tmppin.translate(table, delete_table)
      pinlen = len(tmppin)
      if pinlen < query.otpdigits:
        out = "status=BAD_PIN"
        return(out)
      key = tmppin[:pinlen - query.otpdigits]
      pin = tmppin[pinlen - query.otpdigits:]
      hconfig['pincode'] = key
      hconfig['seed'] = query.seed
      hconfig['iv'] = query.iv
      hconfig['counter'] = query.sequence
      hconfig['digits'] = query.otpdigits
      # need to fix generator to work correctly with bad pin
      gen = hotpy.OTPGenerator(hconfig)
      for loop in range(0, 10):
        genpin = gen.getOTP()
        if genpin == pin:
           success = 1
           break
      if success:
        out = "status=OK"
        query.sequence = query.sequence + loop + 1
        query.put()
	break
    if success != 1:
      out = "status=FAILED"
  else:
    out = "status=BAD_ID"
  return(out)

class OtpPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    if self.request.get('id') and self.request.get('pin'):
      out = calc_otp(self.request)
      self.response.out.write("%s\n" % out)
    else:
      self.response.out.write("status=MISSING_PARAMETER\n")


class DemoPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/html'
    path = os.path.join(os.path.dirname(__file__), 'template/demo.html')
    self.response.out.write(template.render(path, None))

  def post(self):
    self.response.headers['Content-Type'] = 'text/plain'
    if self.request.get('id') and self.request.get('pin'):
      out = calc_otp(self.request)
      self.response.out.write("%s\n" % out)
    else:
      self.response.out.write("status=MISSING_PARAMETER\n")


class AdminPage(webapp.RequestHandler):
  def get(self):
    admin = 0
    login = 0
    self.response.headers['Content-Type'] = 'text/html'
    user = users.get_current_user()
    logout_url = users.create_logout_url(self.request.uri)
    login_url = users.create_login_url(self.request.uri)
    if user:
      login = 1
    if users.is_current_user_admin():
      admin = 1
    template_values = { 'login' : login, 'admin' : admin,
      'login_url' : login_url, 'logout_url' : logout_url }
    path = os.path.join(os.path.dirname(__file__), 'template/admin.html')
    self.response.out.write(template.render(path, template_values))


  def post(self):
    user = users.get_current_user()
    if user and users.is_current_user_admin():
      self.response.headers['Content-Type'] = 'text/plain'
      id=self.request.get('id')
      serialno=self.request.get('serialno')
      sequence=self.request.get('sequence')
      pin=self.request.get('pin')
      seed=self.request.get('seed')
      otpdigits=self.request.get('otpdigits')

      iv = binascii.b2a_hex(os.urandom(16))
      hconfig = {}
      hconfig['pincode'] = pin
      hconfig['seed'] = seed
      hconfig['iv'] = iv
      encseed = hotpy.OTPGenerator(hconfig)
      eseed = encseed.cryptSeed()

      self.response.out.write("id = %s\n" % id)
      self.response.out.write("serialno = %s\n" % serialno)
      self.response.out.write("sequence = %s\n" % sequence)
      self.response.out.write("pin = %s\n" % pin)
      self.response.out.write("seed = %s\n" % seed)
      self.response.out.write("iv = %s\n" % iv)
      self.response.out.write("eseed = %s\n" % eseed)
      self.response.out.write("otp digits = %s\n" % otpdigits)
      hdata = HotpData(id=id,
        serialno=serialno,
        iv=iv,
        seed=eseed,
        sequence=int(sequence),
	otpdigits=int(otpdigits))
      hdata.put()
    else:
      self.response.out.write("Access Denied.")

application = webapp.WSGIApplication(
                                     [('/otp', OtpPage),
                                     ('/admin', AdminPage),
                                     ('/demo', DemoPage)],
                                     debug=False)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
