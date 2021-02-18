# Returns a clean string
def clean_string(incoming_string):
	# If it starts with .\, we remove those chars
	if incoming_string[0:2] == ".\\":
		new_string = incoming_string[2:]
	else:
		new_string = incoming_string

	new_string = new_string.replace("!","")
	new_string = new_string.replace("@","")
	new_string = new_string.replace("#","")
	new_string = new_string.replace("$","")
	new_string = new_string.replace("%","")
	new_string = new_string.replace("^","")
	new_string = new_string.replace("&","and")
	new_string = new_string.replace("*","")
	new_string = new_string.replace("(","")
	new_string = new_string.replace(")","")
	new_string = new_string.replace("+","")
	new_string = new_string.replace("=","")
	new_string = new_string.replace("?","")
	new_string = new_string.replace("\'","")
	new_string = new_string.replace("\"","")
	new_string = new_string.replace("{","")
	new_string = new_string.replace("}","")
	new_string = new_string.replace("[","")
	new_string = new_string.replace("]","")
	new_string = new_string.replace("<","")
	new_string = new_string.replace(">","")
	new_string = new_string.replace("~","")
	new_string = new_string.replace("`","")
	new_string = new_string.replace(":","")
	new_string = new_string.replace(";","")
	new_string = new_string.replace("|","")
	new_string = new_string.replace("\\","")
	new_string = new_string.replace("/","")
	return new_string