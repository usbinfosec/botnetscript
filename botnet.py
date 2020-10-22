
from __future__ import print_function
from apiclient import errors
from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools
from oauth2client import file
from apiclient.discovery import build
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os.path
import os
import pickle
import httplib2
import base64
import tabula
import csv
import time
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
import mimetypes
import datetime
import collections
from dateutil.parser import parse
import re



SCOPES = ['https://mail.google.com/']   #Modify scopes to restrict or increase acess of app, if modified delete token.pickle
CLIENT_SECRET_PATH = '/home/abenchaita/botnet/credentials.json' #Credential files downloaded from Gmail Api console
TOKEN = '/home/abenchaita/botnet/token.pickle'
OUTPUT = '/home/abenchaita/botnet/output.csv'
OUTPUT_TWO = '/home/abenchaita/botnet/output2.csv' 

def get_service():			#This method authenticates to the gmail acount, first time requires user to click accept
    creds = None
    if os.path.exists(TOKEN):					#if the token.pickle not found a new one is created which requires the user to authenticate
        with open(TOKEN, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:		#if the token has expired it will be refreshed not requirering futher authentication
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file( CLIENT_SECRET_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN, 'wb') as token:
            pickle.dump(creds, token)							#Save the credentials for the next run

    service = build('gmail', 'v1', credentials=creds)
    return service 											#returns service object required to use gmail api methods



"""List all Messages of the user's mailbox matching the query.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    query: String used to filter messages returned.
    Eg.- 'from:user@some_domain.com' for Messages from a particular sender.

  Returns:
    List of Messages that match the criteria of the query. Note that the
    returned list contains Message IDs, you must use get with the
    appropriate ID to get the details of a Message.
 """

def listMessagesMatchingQuery(service, user_id, query=''): 

  try:
    response = service.users().messages().list(userId=user_id,q=query).execute()
    messages = []
    if 'messages' in response:
      messages.extend(response['messages'])

    while 'nextPageToken' in response:
      page_token = response['nextPageToken']
      response = service.users().messages().list(userId=user_id, q=query,
                                         pageToken=page_token).execute()
      messages.extend(response['messages'])

    return messages
  except errors.HttpError as error:
    print('An error occurred: %s' % error)


def add_label_to_email(service, user_id, msg_id):
    msg_labels = create_message_label(service)

    try:
        message = service.users().messages().modify(userId=user_id,
                                                id=msg_id,
                                                body=msg_labels).execute()

    except errors.HttpError as error:
        print('An error occurred: %s' % error)


def create_message_label(service):
    removeLabels = GetLabelIds(service,['UNREAD'])
    addLabels = GetLabelIds(service,['Botnet_Processed'])
    return {'removeLabelIds': removeLabels, 'addLabelIds': addLabels}

def GetLabelIds(service, labels_in):
    result = []
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])

    for label_in in labels_in:
        for label in labels:
            if label['name'] == label_in:
                result.append(label['id'])
                break
    return result

"""Get and store attachment from Message with given id in local directory.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    msg_id: ID of Message containing attachment.
"""

def get_attachments(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()

        for part in message['payload']['parts']:
            if part['filename']:
                if 'data' in part['body']:
                    data = part['body']['data']
                else:
                    att_id = part['body']['attachmentId']
                    att = service.users().messages().attachments().get(userId=user_id, messageId=msg_id,id=att_id).execute()
                    data = att['data']
                file_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
                path ='./'+ part['filename']

                with open(path, 'wb') as f:
                    f.write(file_data)

    except errors.HttpError as error:
        print(('An error occurred: %s' % error))


"""Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.

  Returns:
    An object containing a base64url encoded email object.
"""

def create_message(sender, to, subject, message_text):		
  message = MIMEText(message_text)
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  raw = base64.urlsafe_b64encode(message.as_bytes())
  raw = raw.decode()
  return {'raw': raw}



"""Send an email message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message: Message to be sent.

  Returns:
    Sent Message.
"""

def send_message(service, user_id, message):	

  try:
    message = (service.users().messages().send(userId=user_id, body=message)
               .execute())
    print(('Message Id: %s' % message['id']))
    return message
  except errors.HttpError as error:
    print(('An error occurred: %s' % error))


"""Checks whether a user has already appeared on the report either with the same malware or within 2 weeks

  Args:
    user: netId

  Returns:
    False if user recently existed on the report with the same malware
    True if user did not
"""


def not_duplicate(user):
    with open(OUTPUT_TWO, 'rt') as f:
         count = collections.Counter()
         reader = csv.reader(f, delimiter=',') 
         for row in reader:
            if row[2] == user and parse(row[5]) > (datetime.datetime.now() + datetime.timedelta(weeks = -2)): #Check if the user was added less than 2 weeks ago
                description = row[4]
                endIndex = description.index(')')
                ending = description[endIndex+1:]
                counter = (ending + row[2])				#Parse out malware from description and compare
                count[counter]+=1
                if count[counter] >= 1:
                   return False
         return True


"""Takes the botnet report and appends lines that meet the specified crietera to output2.csv, which contains all the botnet tickets and their respective timestamps.
    	After making sure the line is not a duplicate, the line is turned into an email and sent to specified address so that a ticket can be generated.
  Args:
    botnet: name or path of botnet report

 	Output2.csv is saved in the local directory
"""

def botnet():
  titleNotWritten = True
  current_time = datetime.datetime.now()
  tabula.convert_into("./2-onepage.pdf", "foo.csv", stream = True, guess = False,  pages = "all")
  with open('foo.csv', 'r') as f, open(OUTPUT,'w') as o:
      next(f)
      next(f)
      line = f.readline()
      line = line[:10]+ ',' +line[11:25]+','+line[26:37]+','+line[38:52]+',Description'+'\n'
      o.write(line)
      for line in f:
          if ord(line[0]) > 57:
              o.write(line)
              continue
          line = line[:1] +',' + line[2:]
          m = re.search(r'[a-z]', line)
          user = m.start()
          if line[user-1] == ',':
              line = line[:user-1] + line[user:]
          else:
              line = line[:user-1] +',' +line[user:]
          system =  line.find('vsys1')
          line = line[:system-1] +','+line[system:system+5] +','+line[system+6:]
          o.write(line)

  with open(OUTPUT, 'r') as inp, open(OUTPUT_TWO, 'a+') as out:
      writer = csv.writer(out)
      for row in csv.reader(inp):
          if row[0] == "Confidence" and titleNotWritten:
              titleNotWritten = False
              datem = datetime.datetime(current_time.year, current_time.month, current_time.day)
              datem = datem - datetime.timedelta(days=1)
              row.append(str(datem.date()))
              writer.writerow(row)
          if row[0] == "4":
              row.append(str(datem.date()))
              description = row[4]
              endIndex = description.index(')')
              numHits = description[20:endIndex]									#Parsing of criteria
              ending = description[endIndex+1:]
              if int(numHits) >= 100  and row[2] != "unknown user":
                  if(not_duplicate(row[2])):
                      writer.writerow(row)
                      testMessage = create_message('me', 'masergy@connect.stonybrook.edu', 'Alert - Malicious Web Traffic', ', '.join(row))
                      time.sleep(2)																												#Waiting for 2 seconds minimizes message sending failure
                      testSend = send_message(service, 'me', testMessage)




if __name__ == "__main__":
    service = get_service()
    ids = listMessagesMatchingQuery(service,'me', query='from:pa-7080@noc.stonybrook.edu, is:unread') 
    messageId = ids[0].get('id') 
    get_attachments(service, 'me', messageId)
    add_label_to_email(service, 'me', messageId)
    botnet()


