import smtplib
to = 'yoendricoropesa@gmail.com'
gmail_user = 'tramiteleco001@gmail.com'
gmail_pwd = '1Oropesa2.'
smtpserver = smtplib.SMTP("smtp.gmail.com", 587, tls=False)
smtpserver.helo()
smtpserver.login(gmail_user, gmail_pwd)
header = 'To:' + to + '\n' + 'From: ' + gmail_user + '\n' + 'Subject: Email from the WiPy \n'
msg = header + '\n Hi, \n this is The WiPy emailing ;-) \n\n Cheers, \n The WiPy'
smtpserver.sendmail(gmail_user, to, msg)
smtpserver.close()
