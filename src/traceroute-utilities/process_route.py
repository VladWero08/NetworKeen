import random
import json

# for geoplotting
import pandas
import geopandas
import pycountry
import matplotlib.pyplot as plt

# generate random number for dictionary key
def generate_location(JSON_input_dict):
    number_generated = str(random.randint(0,10000))
    # until a new key is found, generate new random numbers
    while ("discovered_from_" + number_generated) in JSON_input_dict:
        number_generated = str(random.randint(0,10000))
    return number_generated

# save the route into a JSON and the location
# where the code was executed
def save_route_in_JSON(IP_information, JSON_file, location=None):
    # firstly read the JSON file
    with open(JSON_file, "r") as JSON_input:
        JSON_input_dict = json.load(JSON_input)

    if location == None:
        execution_location = "discovered_from_" + generate_location(JSON_input_dict)
    else:
        execution_location = "discovered_from_" + location

    # add the location as a key with the value of the root
    # into the JSON file
    JSON_input_dict[execution_location] = IP_information
    with open(JSON_file, "w") as JSON_output:
        json.dump(JSON_input_dict, JSON_output, indent=5)

def plot_route_in_world_map(IP_informations):
    # load the world map
    world = geopandas.read_file(geopandas.datasets.get_path('naturalearth_lowres'))

    # load all the country codes
    with open('src/traceroute-utilities/country_codes.json', "r") as JSON_input:
        country_codes = json.load(JSON_input)
    # initiate the country codes with 0
    for country in country_codes:
        country_codes[country] = 0

    # for each IP address, increment the corresponding
    # country appearance
    for IP_address in IP_informations:
        country_code = IP_informations[IP_address]["country"]
        if country_code != "unavailable":
            country_codes[country_code] += 1

    # transform the dictionary of country codes & frequencies
    # to iso_a3 format that is compatible with geopandas' world map
    country_codes_iso_a3 = {}
    for country, frequency in country_codes.items():
        try:
            country_iso_a3 = pycountry.countries.lookup(country).alpha_3
            country_codes_iso_a3[country_iso_a3] = frequency
        except:
            pass

    # create a data frame with iso_a3 country
    world_data_frame = pandas.DataFrame(list(country_codes_iso_a3.items()), columns=['iso_a3', 'data'])
    world = world.merge(world_data_frame, on='iso_a3', how='left')

    fig, ax = plt.subplots(figsize=(10, 6))
    world.plot(ax=ax,
               column='data',
               legend=True,
               legend_kwds={'label': "Number of traversals through the country",
                            'orientation': "horizontal"})
    plt.show()