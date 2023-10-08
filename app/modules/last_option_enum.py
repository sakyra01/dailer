from datetime import datetime, timedelta


def date_calculation(arg):
    date_range = []
    current_date = datetime.now()
    new_date = current_date - timedelta(days=arg)   # Get comparison of dates

    while new_date <= current_date:
        date_range.append(new_date.strftime("%Y-%m-%d"))
        new_date += timedelta(days=1)
    return date_range
