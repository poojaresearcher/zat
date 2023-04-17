import time,datetime

def sleep_till_future(f_minute):
    """The function takes the current time, and calculates for how many seconds should sleep until a user provided minute in the future."""       
    t = datetime.datetime.today()
    future = datetime.datetime(t.year,t.month,t.day,t.hour,f_minute)
    if future.minute <= t.minute:
        print("ERROR! Enter a valid minute in the future.")
    else:
        print "Current time: " + str(t.hour)+":"+str(t.minute)
        print "Sleep until : " + str(future.hour)+":"+str(future.minute)
        seconds_till_future = (future-t).seconds
        time.sleep( seconds_till_future )
        print "I slept for "+str(seconds_till_future)+" seconds!"
