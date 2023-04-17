def start():
    time_periods = working_periods_table.find_all()
    today = datetime.datetime.now().isoweekday()
    for day in time_periods:
        if day["day"] == today:
            start_time = day["work_start_at"]
            end_time = day["work_end_at"]

    schedule.every().week.at(start_time).do(record_activity(idle_time=300))
