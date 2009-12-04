This is a OATH validating server written for the google appengine platform.
The server responses are inspired by the yubi authentication server.
Validation expects a connection to http://server/otp?id=[id]&pin=[pin] where
the id is the id associated with your oath device and the pin is the otp
prefixed with a pin.  A new id, pin, and seed value may be added via the admin
interface at http://server/admin.  Multiple tokens can be assigned the same id
and each will be checked.  Because of that, the admin interface requires an id
(not necessarily unique), a serial number to uniquely identify the device, the
number of OTP digits generated, the current sequence number, a pin (which is
used to encrypt the seed record, and the seed itself.  There is not currently
an interface to view the loaded records, but they can be reviewed using the
appengine database viewer.
