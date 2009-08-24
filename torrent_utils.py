#from django.contrib.sites.admin import Site
from hashlib import sha1
import base64
from bencode import bencode, bdecode

import urllib
import urllib2


def human(num, suffix='b'):
    num=float(num)
    for x in ['','K','M','G','T']:
        if num<1024:
            return "%3.1f%s%s" % (num, x, suffix)
        num /=1024

def compact_decode( data='\x7f\x00\x00\x01)\n' ):
    peers = []
    for i in xrange(len(data)/6):
        peer_str = data[i*6:i*6+6]
        ip = '.'.join( [str(ord(ip)) for ip in peer_str[:4]] )
        port = int('%X%X'%tuple([ord(p) for p in peer_str[4:6]]), 16)
        peer_str = '%s:%d'%(ip, port)
        peer = {'ip': ip, 'port': port, 'peer_id': None }
        peers.append(peer)
    return peers

def compact_encode( data= [{'ip': '127.0.0.1', 'port': 666, 'peer_id': None },] ):
    peers_list=[]
    for d in data:
        ip_str =''.join([ chr(int(i)) for i in d['ip'].split('.')])
        port_hex = hex( d['port'])[2:]
        port_str = chr(int(port_hex[:2],16))+chr(int(port_hex[2:],16))
        peer_str = ip_str+port_str
        peers_list.append( peer_str)
    peers_str = ''.join( peers_list )
    return peers_str

def randstring(length):
    "Returns a random alphanumeric string of length length."
    import random
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
    string = ''
    for y in range(length):
        string += random.choice(alphabet)
    return string

class TorrentParser:
    '''
    tp = TorrentParser( '1.torrent')
    tp.get_info_hash()
    tp.add_announce('http://example.org:6969/announce')

    '''
    meta = {}
    meta_info = {}
    def __init__(self, obj):
        if type(obj) is str:
            if obj.endswith('.torrent'):
                f = open( obj, 'rb')
                string = f.read()
                f.close()
            else:
                string = obj
        elif type(obj) is file or obj.__module__ == 'StringIO':
            string = obj.read()
            obj.close()
        self.meta = bdecode(string)
        self.meta_info = self.meta['info']

    def get_name(self):
        return self.meta_info['name']

    def get_info_hash(self):
        return sha1( bencode(self.meta_info) ).digest()

    def get_info_hash_base64(self):
        return base64.b64encode(self.get_info_hash())

    def get_info_hash_quoted(self):
        return urllib.quote( self.get_info_hash() )

    def get_size(self):
        files = self.meta_info.get('files')
        if files:
            return sum([f['length'] for f in files])
        else:
            return self.meta_info['length']

    def get_file(self):
        return bencode(self.meta)

    def get_filenames_and_size(self, json=True):
        files = self.meta_info.get('files')
        if files:
            file_and_size = [ {
                'file':'/'.join(f.get('path.utf-8') or f.get('path')),
                'size': f['length']} for f in files ]
        else:
            file_and_size = [{
                'file': self.meta_info.get('name.utf-8') or self.meta_info.get('name') ,
                'size':self.meta_info['length']
                }]
        if json:
            from json import dumps
            return dumps( file_and_size )
        else:
            return file_and_size

    def get_announce_list(self):
        anon = [self.meta['announce']]
        anon_list = self.meta.get('announce-list')
        if anon_list:
            anon.extend( [ m[0] for m in anon_list])
        return list( set(anon) )

    def add_announce(self, url, end=False):
        if self.meta.get('announce-list'):
            if end:
                self.meta['announce-list'].append([url])
            else:
                self.meta['announce-list'].insert(0,[url])
        else:
            self.meta['announce-list'] = [[url], [self.meta['announce']]]
    def remove_all_anounce( self):
        self.meta['announce-list'] = []
        self.meta['announce'] = ''

# RatioMaster - fake bittorent client for testing tracker
class FakeClient:
    example = {
            'peer_id':'',
            'headers':[('',''),('','')]
            }
    transmission = {'peer_id':'-TR1730-','headers':[('User-Agent','Transmission/1.73 (8831)')]}
    utorrent = {'peer_id':'-UT1800-','headers':[()],}
    vzue = {'peer_id':'-AZ4204-',
            'headers':[('User-Agent','Azureus 4.2.0.4;Linux;Java 1.6.0_14')]
            }
    deluge = {
            'peer_id':'-DE1190-',
            'headers':[('User-Agent','Deluge 1.1.9'),]
            }

class RatioMaster:
    '''
    rm = RatioMaster()
    rm.load_torrent( '1.torrent')
    rm.setup(announce='http://example.com/announce')
    rm.get_peer_list()

    '''
    started = True
    query = {
            'info_hash':'',
            'peer_id':'',
            'downloaded':0,
            'uploaded':0,
            'corrupt':1,
            'port':'6881',
            'compact':'0',
            'left':0,
            'numwant':'10',
            'no_peer_id':'1',
            #'event':'',
            #'key':randstring(12),
            }
    qyery_order = ('info_hash','peer_id','downloaded','corrupt','port','compact','numwant')
    session_key = None
    uploaded = 0
    downloaded = 0
    config_func = dict(
            info_hash = lambda x=None: config.update({'info_hash':x}) if x else x,
            announce=lambda x=[]:  map( lambda y:y, x if type(x) is list else [x] ),
            proxy_http=lambda x=None: {'http':x} if x else x,# 'http://127.0.0.1:8118'
            client=lambda x=FakeClient.deluge: x,
            port=lambda x=6881: x,
            upload_speed=lambda x=100:x*1024/8,# in Kb
            download_speed=lambda x=0:x*1024/8,# in Kb
            finished=lambda x=100: x,# %
            update_time=lambda x=1800: x,# seconds
            debug=lambda x=False: x,

            )
    def __init__(self):
        self.config=dict([ (k, v()) for k,v in self.config_func.items()])
        pass
    def debug(self, msg):
        if self.config['debug']:
            print msg

    def load_meta(self, _file):
        f = open(_file, 'rb')
        data=f.read()
        f.close()
        self.tp = TorrentParser( data )
        self.info_hash = self.tp.get_info_hash()
        self.announce = self.tp.get_announce_list()
        self.t_size = self.tp.get_size()
        self.publisher_url = self.tp.meta.get('publisher-url')
        print self.announce
        print self.publisher_url
    def setup(self, **kwargs ):
        '%s'%str( self.config )
        for key,val in kwargs.items():
            conf_f = self.config_func.get(key)
            if conf_f:
                self.config.update({key: conf_f( val )})

    def make_get_url( self, url):
        from cgi import parse_qs
        query = self.query
        print query
        query_url = urllib.splitquery(url)[1]
        if query_url is not None:
            query_url = parse_qs( query_url )
            query.update( dict([(k,''.join(v)) for k,v in query_url.items() ]) )
        result_url = '?'.join( [url, urllib.urlencode( query ) ] )
        return result_url

    def send(self):
        self.query.update( {'downloaded':self.downloaded, 'uploaded':self.uploaded, 'left': self.left } )
        self.response = []
        if self.config['announce']:
            self.announce = self.config['announce']
        for a in self.announce:
            url = self.make_get_url( a )

            if self.config['proxy_http']:
                u=urllib.FancyURLopener(proxies=self.config['proxy_http'])
            else:
                u=urllib.FancyURLopener()
            headers = self.config['client']['headers']+[('Connection','close')] 
            u.addheaders = headers
            #u.addheaders.append()
            error = True
            for i in xrange(3):
                _u = u.open( url )
                self.debug( url)
                if _u.code == 200:
                    self.response.append( (a,_u.read()) )
                    break
                    self.debug( '%s\n%s'%(  _u.code, _u.read()) )
                elif _u.code == 404:
                    print 'Error 404'
                    break
                else:
                    print _u.read(), _u.code

    def update_config(self):
        self.query.update(
                {
                    'port': self.config['port'],
                    'peer_id': self.config['client']['peer_id']+randstring(12),
                    'info_hash': self.info_hash,
                    } )
        self.left = (100-self.config['finished'] )*self.t_size/100

    def update(self,send=False, stopped=False):
        self.uploaded += self.temp_time * self.config['upload_speed']
        self.downloaded += self.temp_time * self.config['download_speed']
        #print self.left, self.uploaded, self.downloaded
        if self.left <= 0 and self.config['download_speed'] != 0:
            self.left = 0
            self.config['download_speed'] = 0
            self.query.update({'event':'completed'})
        else:
            self.left -= self.temp_time * self.config['download_speed']

        if stopped:
            'Stopped...'
            self.query.update({'event':'stopped'})
            pass
        elif self.started:
            print 'Started...'
            self.query.update({'event':'started'})
            self.started = False
        if not self.started:
            if self.query.get('event'):
                self.query.pop('event')
            #self.query.update({'event':''})
            pass
        if send:
            self.send()

    def verbose(self):
        _t = human( self.t_size, suffix='b',),\
             human( self.uploaded, suffix='b'),\
             human( self.downloaded, suffix='b')
        print 'Size: %s; Uploaded: %s; Downloaded: %s;\r'%_t,

    def start(self):
        self.update_config()
        self.all_time = 0
        self.temp_time=0
        start = time.time()
        self.verbose()
        self.update(send=True)
        try:
            while True:
                self.temp_time = int(time.time() - start)
                self.update()
                self.verbose()
                time.sleep(0.5)
                if self.temp_time >= self.config['update_time']:
                    self.all_time += self.temp_time
                    self.update(send=True)
                    self.temp_time = 0
                    start = time.time()
        except KeyboardInterrupt:
            self.update(send=True,stopped=True)

    def get_peers( self ):
        self.update_config()
        self.query.update({'event':'started'})
        self.send()
        for announce, bencoded_responce in self.response:
            dec_r = bdecode( bencoded_responce )
            print announce
            if type(dec_r['peers']) is str:
                pass
                dec_r['peers'] = compact_decode( dec_r['peers'] )

            print dec_r
        self.query.update({'event':'stopped'})
        self.send()


def test_tp( torrentfile ):
    f = open( torrentfile, 'r')
    tp = TorrentParser( f.read())
    f.close()
    print tp.get_name()
    print tp.get_announce_list()
    print tp.get_info_hash_base64()
def test_rm( torrentfile ):
    rm=RatioMaster()
    rm.load_meta( torrentfile )
    rm.setup( debug=True)
    rm.get_peers()



if __name__ == '__main__':
    test_rm('1.torrent')


