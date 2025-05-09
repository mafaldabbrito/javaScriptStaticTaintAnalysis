from models.pattern import Pattern
from models.multilabel import MultiLabel


if __name__ == "__main__":
    # Define patterns
    sql_pattern = Pattern("SQL Injection", ["get_user_input"], ["escape_sql"], ["execute_query"])
    xss_pattern = Pattern("XSS", ["get_url_param"], ["sanitize_html"], ["render_page"])

    # Create MultiLabel
    mlabel = MultiLabel([sql_pattern, xss_pattern])

    # Add valid sources/sanitizers
    mlabel.add_source("SQL Injection", "get_user_input")     
    mlabel.add_sanitizer("SQL Injection", "get_user_input","escape_sql")      

    mlabel.add_source("XSS", "get_url_param")                
    mlabel.add_sanitizer("XSS", "get_user_input", "sanitize_html")              

    # Invalid (ignored silently or could raise an error, depending on design)
    mlabel.add_source("SQL Injection", "get_url_param")       # not a valid source for SQL

    # Combine with another MultiLabel
    mlabel2 = MultiLabel([sql_pattern, xss_pattern])
    mlabel2.add_source("SQL Injection", "get_user_input")

    combined = mlabel.combine(mlabel2)



