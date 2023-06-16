#my token 
import ipinfo


def inspect_IP_addresses(IP_address, IP_address_informations, access_token = 'c7e3a0fd8c3f42'):
    IP_handler = ipinfo.getHandler(access_token)

    # for each IP_address found in the route to the destination IP
    # extract information regarding: city, region, country
    IP_address_informations[IP_address] = {}
    IP_details = IP_handler.getDetails(IP_address)

    # try extracting the city
    try:
        IP_address_informations[IP_address]["city"] = IP_details.city
    except:
        IP_address_informations[IP_address]["city"] = "unavailable"

    # try extracting the region
    try:
        IP_address_informations[IP_address]["region"] = IP_details.region
    except:
        IP_address_informations[IP_address]["region"] = "unavailable"

    # try extracting the country
    try:
        IP_address_informations[IP_address]["country"] = IP_details.country
    except:
        IP_address_informations[IP_address]["country"] = "unavailable"

# display information about each IP in the route
def display_route(IP_informations):
    # for each IP display city, region, country
    # as well as the IP address itself
    for IP_entry in IP_informations:
        print(f"ip: {IP_entry}, city: {IP_informations[IP_entry]['city']}, region: {IP_informations[IP_entry]['region']}, country: {IP_informations[IP_entry]['country']}")

