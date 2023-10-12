def time_to_term(seconds):
    return f't{str(seconds).replace(".", "_")}'

def term_to_time(term):
    return float(term[1:].replace("_", "."))