import re
req = "GET / HTTP/1.0\r\nHost: www.google.com\r\nAccept: application/json\r\n\r\n"

r1 = req.split('\n')[0]
print(r1)
method = r1.split()[0]
print(method)
path = r1.split()[1]
print(path)
if (path == "/"):
    r2 = req.split('\n')[1]
    print(r2)
    host = r2.split()[0]
    print(host)
    if (host == "Host:"):
        host = re.sub("[:]","",host)
        print(host)
        url = r2.split()[1]
        print(url)
        mylist=[]
        mylist.append(host)
        mylist.append(url)
        print(mylist)
    portno=re.findall(r'[0-9]+',r2)
    print(portno)
    if portno==[]:
      portno="80"
      print(portno)
    r3=req.split('\n')[2]
    if(r3!=''):
     print(r3)
     title=r3.split()[0]
     title= re.sub("[:]","",title)
     print(title)
     value=r3.split()[1]
     print(value)
     lists = []
     lists.append(title)
     lists.append(value)
     print(lists)
     mylist.append(lists)
     mylist
     print(mylist)
    else:
        print("Hello")


