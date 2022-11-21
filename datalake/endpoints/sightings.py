from datalake import ThreatType, SightingType, Visibility, SightingRelation
from datalake.endpoints.endpoint import Endpoint
from datalake.common.atom_type import Atom
from datetime import datetime
from typing import List


class Sightings(Endpoint):
    def submit_sighting(self, start_timestamp: datetime, end_timestamp: datetime, sighting_type: SightingType,
                        visibility: Visibility, count: int, threat_types: List[ThreatType] = None,
                        tags: List[str] = None, description: str = None,
                        atoms: List[Atom] = None, hashkeys: List[str] = None, relation: SightingRelation = None,
                        editable: bool = None):
        """
        Submit a list of sightings.
        Either threat hashkeys or list of atom objects is required.
        Possible sightings type: POSITIVE, NEGATIVE, NEUTRAL. For POSITIVE and NEGATIVE sightings "threat_types"
        field is required. End date timestamp should always be in the past.
        relation field requires specific permission for the user.
        """
        payload = self._prepare_sightings_payload(atoms, hashkeys, start_timestamp, end_timestamp, sighting_type,
                                                  visibility, count, threat_types, tags, description, relation, editable)
        url = self._build_url_for_endpoint('submit-sightings')
        res = self.datalake_requests(url, 'post', self._post_headers(), payload).json()
        return res

    @staticmethod
    def _check_sightings_payload_parameters(atoms, hashkeys, sighting_type, visibility, count, threat_types, relation):
        if not atoms and not hashkeys:
            raise ValueError('Either threat hashkeys or list of atom objects is required.')
        if count < 1:
            raise ValueError('count value minimum: 1')
        if not isinstance(sighting_type, SightingType):
            raise ValueError('sighting_type has to be an instance of the SightingType class.')
        if sighting_type in (SightingType.POSITIVE, SightingType.NEGATIVE):
            if not threat_types or not all(isinstance(threat_type, ThreatType) for threat_type in threat_types):
                raise ValueError('For POSITIVE and NEGATIVE sightings "threat_types" field is required and has to be '
                                 'an instance of the Visibility class')
        elif threat_types:
            raise ValueError("For NEUTRAL sightings, threat_types can't be passed.")
        if not isinstance(visibility, Visibility):
            raise ValueError('visibility has to be an instance of the Visibility class.')
        if relation and not isinstance(relation, SightingRelation):
            raise ValueError('relation has to be an instance of the SightingRelation class.')

    def _prepare_sightings_payload(self, atoms, hashkeys, start_timestamp, end_timestamp, sighting_type: SightingType,
                                   visibility, count, threat_types=None, tags=None, description=None, relation=None,
                                   editable=None):
        """
        Internal function to prepare a list of Atoms for sighting submission to the format the API expects.
        """
        self._check_sightings_payload_parameters(atoms, hashkeys, sighting_type, visibility, count, threat_types,
                                                 relation)
        payload = {}
        # atoms and hashkeys can both be None
        if atoms:
            for atom in atoms:
                if type(atom) == Atom or not isinstance(atom, Atom):
                    raise TypeError("atoms needs to be a list of Atom subclasses.")
                atom_dict = atom.generate_atom_json(for_sightings=True)
                if not payload:
                    payload = atom_dict
                else:
                    payload = {
                        key: payload.get(key, []) + atom_dict.get(key, [])
                        for key in set(
                            list(payload.keys()) + list(atom_dict.keys())
                        )
                    }

        if hashkeys:
            payload['hashkeys'] = hashkeys

        payload['start_timestamp'] = start_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        payload['end_timestamp'] = end_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        payload['visibility'] = visibility.value
        payload['type'] = sighting_type.value
        payload['count'] = count

        if relation:
            payload['relation_type'] = relation.value
        if sighting_type in (SightingType.POSITIVE, SightingType.NEGATIVE):
            payload['threat_types'] = [threat_type.value for threat_type in threat_types]
        if tags:
            payload['tags'] = tags
        if description:
            payload['description'] = description
        if editable is not None:
            payload['editable'] = editable
        return payload
