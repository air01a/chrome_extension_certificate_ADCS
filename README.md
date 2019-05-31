# chrome_extension_certificate_ADCS
Use google auth to generate certficiate for user on AD

This extension just get the auth token from google, and send it to the python script.
The python script get the token, validate it, get the user email, find the user information in the active directory with this email, and generate the certificate according to all these information.

It was a Proof Of Concept to develop an API and extension to manage user certicate on chromebook computer for the wifi and adfs access. 
The real application is under developpment and will be used on production.
