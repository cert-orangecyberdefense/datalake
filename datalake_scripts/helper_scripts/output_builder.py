import json


class CsvBuilder:

    @staticmethod
    def create_csv(complete_response, atom_type):
        complete_csv = ['hashkey,atom_type,atom_value_best_matching,atom_found,events_number,first_seen,last_updated,'
                        'threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,'
                        'malware.score.risk,phishing.score.risk,scam.score.risk,spam.score.risk,sources,tags,'
                        'href_graph,href_history,href_threat,href_threat_webGUI']

        for threat in complete_response.keys():
            response = complete_response[threat]
            if 'threat_found' in response.keys():  # means threat not found
                line = f"{response['hashkey']},{atom_type},{threat},{False}," + ','.join([f"{None}"] * 18)
            else:
                threat_scores = CsvBuilder._load_scores(response['scores'])
                threat_types = ','.join(response['threat_types']) if 'threat_types' in response else None
                if threat_types:
                    threat_types = f'"{threat_types}"'

                line = f"{response['hashkey']},{atom_type},{threat},{True}," \
                       f"{CsvBuilder._count_events(response['sources'])},{response['first_seen']}," \
                       f"{response['last_updated']},{threat_types}," \
                       f"{threat_scores.get('ddos')},{threat_scores.get('fraud')}," \
                       f"{threat_scores.get('hack')},{threat_scores.get('leak')},{threat_scores.get('malware')}," \
                       f"{threat_scores.get('phishing')},{threat_scores.get('scam')},{threat_scores.get('spam')}," \
                       f"{CsvBuilder._load_sources(response['sources'])}," \
                       f"{CsvBuilder._create_tags_list(response['tags'])}," \
                       f"{response['href_graph']},{response['href_history']},{response['href_threat']}," \
                       f"{response['href_threat']}"
            complete_csv.append(line)

        return complete_csv

    @staticmethod
    def _count_events(sources):
        tot = 0
        for source in sources:
            tot += int(source['count'])
        return tot

    @staticmethod
    def _load_scores(scores):
        threat_scoring = {}
        for score in scores:
            threat_scoring[score['threat_type']] = score['score']['risk']
        return threat_scoring

    @staticmethod
    def _load_sources(sources):
        return f"\"{','.join([source['source_id'] for source in sources])}\""

    @staticmethod
    def _create_tags_list(tags):
        if not tags:
            return None
        tags = ','.join([tag['name'] for tag in tags]).replace('"', '""')
        return f"\"{tags}\""
