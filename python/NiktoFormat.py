import json
from typing import Dict, List, Union, TextIO, Any
from datetime import datetime
from enum import Enum
import NiktoFormat_pb2

CONST_DATEFORMAT = "%d-%m-%Y %H:%M:%S"

class HTTPMethod(Enum):
    """An enum defining the different HTTP request types

    """
    GET = 1
    POST = 2
    HEAD = 3

def MethodFromString(s: str) -> HTTPMethod:
    """Parses a string and returns the appropriate HTTPMethod

    Arguments:
        s {str} -- A string describing a HTTP Method

    Raises:
        ValueError: If s does not match any known HTTPMethod

    Returns:
        HTTPMethod -- The HTTPMethod described by s
    """
    if s == "GET": return HTTPMethod.GET
    if s == "POST": return HTTPMethod.POST
    if s == "HEAD": return HTTPMethod.HEAD
    raise ValueError("Unknown method!")

def MethodToPBMethod(m: HTTPMethod) -> NiktoFormat_pb2.Scan.Host.Method:
    """Maps an HTTPMethod to a protocol buffer Method

    Arguments:
        m {HTTPMethod} -- An HTTPMethod to be converted

    Returns:
        NiktoFormat_pb2.Scan.Host.Method -- The corresponding Protocol Buffer Method
    """
    if m == HTTPMethod.GET: return NiktoFormat_pb2.Scan.Host.Method.GET
    if m == HTTPMethod.POST: return NiktoFormat_pb2.Scan.Host.Method.POST
    if m == HTTPMethod.HEAD: return NiktoFormat_pb2.Scan.Host.Method.HEAD

def MethodFromPBMethod(m: NiktoFormat_pb2.Scan.Host.Method) -> HTTPMethod:
    """Maps a Protocol Buffer Method enum to a HTTPMethod enum

    Arguments:
        m {NiktoFormat_pb2.Scan.Host.Method} -- The Protocol Buffer Enum to be converted

    Returns:
        HTTPMethod -- The corresponding HTTPMethod
    """
    if m == NiktoFormat_pb2.Scan.Host.Method.GET: return HTTPMethod.GET
    if m == NiktoFormat_pb2.Scan.Host.Method.POST: return HTTPMethodd.POST
    if m == NiktoFormat_pb2.Scan.Host.Method.HEAD: return HTTPMethod.HEAD

class NiktoVuln:
    def __init__(
        self,
        id: int,
        method: HTTPMethod,
        desc: str,
        uri: str,
        link: str
    ) -> None:
        """This class represents a Nikto Vulnerability

        Arguments:
            id {int} -- ID of the vulnerability
            method {HTTPMethod} -- The http method used to trigger the vulnerability
            desc {str} -- A description of the vulnerability
            uri {str} -- The URI where the vulnerability was triggered
            link {str} -- The Link where the vulnerability was triggered
        """
        self._id = id
        self._method = method
        self._desc = desc
        self._uri = uri
        self._link = link

    def ToJSON(self) -> Dict:
        """Returns a dictionary containing the class members

        Returns:
            Dict -- A dictionary containing the class members
        """
        return {
            "id": self._id,
            "method": self._method.name,
            "desc": self._desc,
            "uri": self._uri,
            "link": self._link
        }

    def ToPB(self, msg: NiktoFormat_pb2.Scan.Host.Vuln) -> None:
        """Given a protocol buffer object of the correct type the class members are inserted

        Arguments:
            msg {NiktoFormat_pb2.Scan.Host.Vuln} -- A protocol buffer object where this class should be mapped
        """
        msg.id = self._id
        msg.method = MethodToPBMethod(self._method)
        msg.desc = self._desc
        msg.uri = self._uri
        msg.link = self._link

    def __str__(self) -> str:
        return json.dumps(
            self.ToJSON(),
            indent=4
        )


class NiktoHost:
    def __init__(
        self,
        host: str,
        ip: str,
        port: int,
        starttime: datetime,
        checks: int,
        vulns: List[NiktoVuln]
    ) -> None:
        """A class representing a scanned host from Nikto. Also contains a list of vulnerabilities for this host

        Arguments:
            host {str} -- The hostname
            ip {str} -- The IP that the hostname points to at time of scan
            port {int} -- The port scanned
            starttime {datetime} -- When the scan was initiated for this host
            checks {int} -- How many checks were performed
            vulns {List[NiktoVuln]} -- A list of vulnerabilities
        """
        self._host = host
        self._ip = ip
        self._port = port
        self._starttime = starttime
        self._checks = checks
        self._vulns = vulns

    def ToJSON(self) -> Dict:
        """Builds a dictionary from the class members

        Returns:
            Dict -- A dictionary containing the class members
        """
        return {
            "host": self._host,
            "ip": self._ip,
            "port": self._port,
            "starttime": self._starttime.strftime(CONST_DATEFORMAT),
            "checked": self._checks,
            "vulns": [v.ToJSON() for v in self._vulns]
        }

    def ToPB(self, msg: NiktoFormat_pb2.Scan.Host):
        """Given a Protocol Buffer object, populates it with the class members

        Arguments:
            msg {NiktoFormat_pb2.Scan.Host} -- A Host Protocol Buffer object
        """
        msg.host = self._host
        msg.ip = self._ip
        msg.port = self._port
        msg.starttime = self._starttime.strftime(CONST_DATEFORMAT)
        msg.checks = self._checks
        for vuln in self._vulns:
            vuln_pb2 = msg.vulns.add()
            vuln.ToPB(vuln_pb2)

    def __str__(self) -> str:
        return json.dumps(
            self.ToJSON(),
            indent=4
        )


class NiktoScan:
    def __init__(self, obj: Dict[str, Union[str, Dict, List]] = None) -> None:
        """Represents an entire nikto scan of potentially multiple hosts.
        This is the highest level of abstraction and contains the usefull methods to work with the data.

        Keyword Arguments:
            obj {Dict[str, Union[str, Dict, List]]} -- An optional dictionary structure of the format achived by parsing a nikto xml (default: {None})
        """
        self._hosts = []

        if obj is not None:
            self.Parse(obj)

    def ToJSON(self) -> Dict:
        """Builds a dictionary containing all the members and nested members

        Returns:
            Dict -- A dictionary containing all members and nested members
        """
        return {
            "hosts": [h.ToJSON() for h in self._hosts]
        }

    def Serialize(self, fp: TextIO) -> None:
        """Serialize the class to json

        Arguments:
            fp {TextIO} -- A file descriptor opened with "w"

        Raises:
            IOError: Throws if an error occurs during serialization
        """
        try:
            json.dump(self.ToJSON(), fp)
        except:
            raise IOError("An error occurred during serialization. Check your file descriptor.")

    def SerializePB(self, fp: TextIO) -> None:
        """Serialize the class to a Google Protocol Buffer

        Arguments:
            fp {TextIO} -- A file descriptor opened with "wb"

        Raises:
            IOError: Throws if an error occurs during serialization
        """
        try:
            scan = NiktoFormat_pb2.Scan()
            for host in self._hosts:
                host_pb2 = scan.hosts.add()
                host.ToPB(host_pb2)
            fp.write(scan.SerializeToString())
        except:
            raise IOError("Error when Serializing to Protocol Buffer")

    def Deserialize(self, fp: TextIO) -> None:
        """Loads a json file produced by Serialize

        Arguments:
            fp {TextIO} -- A file descriptor opened with "r"

        Raises:
            IOError: Throws if an error occurs during deserialization
        """
        try:
            j = json.load(fp)
            self.ParseJSON(j)
            del j
        except:
            raise IOError("Error Deserializing JSON!")

    def DeserializePB(self, fp: TextIO) -> None:
        """Loads a file produced from SerializePB

        Arguments:
            fp {TextIO} -- A file descriptor opened with "rb"

        Raises:
            IOError: Throws if an error occurs during Deserialization
        """
        try:
            scan = NiktoFormat_pb2.Scan()
            scan.ParseFromString(fp.read())
            self.ParsePB(scan)
            del scan
        except:
            raise IOError("Error deserializing Protocol Buffer!")

    def ParseJSON(self, json: Dict) -> None:
        """Parses a dictionary from the json files produced by Serialize

        Arguments:
            json {Dict} -- A dictionary following a JSON structure
        """
        self._hosts = []
        for h in json["hosts"]:
            vol = []
            for v in h["vulns"]:
                vol.append(
                    NiktoVuln(
                        v["id"],
                        MethodFromString(v["method"]),
                        v["desc"],
                        v["uri"],
                        v["link"]
                    )
                )
            self._hosts.append(
                NiktoHost(
                    h["host"],
                    h["ip"],
                    h["port"],
                    datetime.strptime(
                        h["starttime"],
                        CONST_DATEFORMAT
                    ),
                    h["checked"],
                    vol
                )
            )

    def ParsePB(self, pb: NiktoFormat_pb2.Scan) -> None:
        """Parses a protocol buffer object as produced by SerializePB

        Arguments:
            pb {NiktoFormat_pb2.Scan} -- A Protocol buffer object
        """
        self._hosts = []
        for h in pb.hosts:
            vol = []
            for v in h.vulns:
                vol.append(
                    NiktoVuln(
                        v.id,
                        MethodFromPBMethod(v.method),
                        v.desc,
                        v.uri,
                        v.link
                    )
                )
            self._hosts.append(
                NiktoHost(
                    h.host,
                    h.ip,
                    h.port,
                    datetime.strptime(
                        h.starttime,
                        CONST_DATEFORMAT
                    ),
                    h.checks,
                    vol
                )
            )

    def Parse(self, obj: Dict[str, Union[str, Dict, List]]) -> None:
        """Parses a dictionary produced by reading a Nikto xml with xmltodict

        Arguments:
            obj {Dict[str, Union[str, Dict, List]]} -- A dictionary of parsed nikto xml

        Raises:
            ValueError: Raises if the input is malformed
        """
        try:
            self._hosts = []
            for h in obj["niktoscan"]["niktoscan"]:
                d = h["scandetails"]
                vol = []
                for v in d["item"]:
                    vol.append(
                        NiktoVuln(
                            int(v["@id"]),
                            MethodFromString(v["@method"]),
                            v["description"],
                            v["uri"],
                            v["namelink"]
                        )
                    )
                self._hosts.append(
                    NiktoHost(
                        d["@targethostname"],
                        d["@targetip"],
                        int(d["@targetport"]),
                        datetime.strptime(
                            d["@starttime"],
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        int(d["@checks"]),
                        vol
                    )
                )
        except:
            raise ValueError("Input structure is not correctly formatted!")

    def __str__(self) -> str:
        return json.dumps(
            self.ToJSON(),
            indent=4
        )