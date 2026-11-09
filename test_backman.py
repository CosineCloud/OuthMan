from datetime import datetime
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import backMan
import backMan_runner
import backups
import server
import test_server


class BackManFlow(unittest.TestCase):
    request = test_server.Flows.request

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_db = server.DB
        server.DB = Path(self.temp.name) / 'db.sqlite3'
        server.initialize()
        self.http = ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        _,_,admin=self.request('/api/login',{'username':'admin@admin.com','password':'pass123'})
        _,_,self.admin=self.request('/api/change-credentials',{'username':'backman-admin','password':'PrivatePassword123!'},admin)
        self.request('/api/acl',{'networks':['127.0.0.1']},self.admin)
        _,self.key,_=self.request('/api/backups/keys',{'name':'BackMan','scope':'backups:create,read'},self.admin)
        self.files={}
        self.upload_count=0
        self.ambiguous=False
        self.ambiguous_on=None
        self.corrupt_download=False
        owner=self
        class CSO(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def reply(self,body,status=200):
                data=body if isinstance(body,bytes) else json.dumps(body).encode()
                self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def authorized(self):
                if self.headers.get('Authorization')!='Bearer test-cso-secret':
                    self.reply({'error':'unauthorized'},401);return False
                return True
            def do_GET(self):
                if not self.authorized():return
                if self.path=='/api/v1/files':
                    return self.reply({'files':[{k:v for k,v in row.items() if k!='bytes'} for row in owner.files.values()]})
                row=owner.files.get(int(self.path.rsplit('/',1)[1]))
                return self.reply((b'corrupt' if owner.corrupt_download else row['bytes']) if row else {'error':'missing'},200 if row else 404)
            def do_POST(self):
                if not self.authorized():return
                body=self.rfile.read(int(self.headers['Content-Length']))
                message=BytesParser(policy=policy.default).parsebytes(b'Content-Type: '+self.headers['Content-Type'].encode()+b'\r\nMIME-Version: 1.0\r\n\r\n'+body)
                parts={part.get_param('name',header='content-disposition'):part.get_payload(decode=True) for part in message.iter_parts()}
                name=parts['path'].decode()
                if any(row['path']==name for row in owner.files.values()):
                    return self.reply({'error':'duplicate'},409)
                owner.upload_count+=1
                row={'id':owner.upload_count,'path':name,'size':len(parts['file']),'bytes':parts['file']}
                owner.files[row['id']]=row
                if owner.ambiguous or owner.ambiguous_on==owner.upload_count:
                    owner.ambiguous=False
                    owner.ambiguous_on=None
                    return self.reply({'error':'simulated lost success'},502)
                return self.reply({k:v for k,v in row.items() if k!='bytes'},201)
        self.cso=ThreadingHTTPServer(('127.0.0.1',0),CSO)
        threading.Thread(target=self.cso.serve_forever,daemon=True).start()
        self.config_path=Path(self.temp.name)/'backMan.json'
        self.config={'work_dir':'work','hosts':[{'name':'outhman','url':f'http://127.0.0.1:{self.http.server_port}','api_key_env':'TEST_HOST_KEY','passphrase_env':'TEST_BACKUP_PASSPHRASE'}],'cso':{'url':f'http://127.0.0.1:{self.cso.server_port}','api_key_env':'TEST_CSO_KEY','path_prefix':'backups'}}
        self.config_path.write_text(json.dumps(self.config))
        self.environment=patch.dict('os.environ',{'TEST_HOST_KEY':self.key['api_key'],'TEST_BACKUP_PASSPHRASE':'a private backman test passphrase','TEST_CSO_KEY':'test-cso-secret'})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.http.shutdown();self.http.server_close()
        self.cso.shutdown();self.cso.server_close()
        self.temp.cleanup();server.DB=self.previous_db

    def test_trigger_key_scopes_and_retry(self):
        self.assertRegex(self.key['api_key'],r'^[0-9a-f]{32}$')
        headers={'Authorization':'Bearer '+self.key['api_key']}
        payload={'request_id':'a'*32,'passphrase':'a private test passphrase'}
        status,created,_=self.request('/api/backups/trigger',payload,extra_headers=headers)
        self.assertEqual(status,201)
        self.assertEqual(len(created['sha256']),64)
        self.assertEqual(self.request('/api/backups/trigger',payload,extra_headers=headers)[1]['id'],created['id'])
        self.assertEqual(len(backups.listing(server.DB)),1)
        self.assertEqual(self.request('/api/backups/trigger',dict(payload,request_id='bad'),extra_headers=headers)[0],400)
        _,read_key,_=self.request('/api/backups/keys',{'name':'Read only'},self.admin)
        self.assertEqual(self.request('/api/backups/trigger',payload,extra_headers={'Authorization':'Bearer '+read_key['api_key']})[0],403)
        self.assertEqual(self.request('/api/backups/restore',{'confirm':True},extra_headers=headers)[0],403)
        self.assertEqual(self.request('/api/backups/keys',{'name':'escalate'},extra_headers=headers)[0],403)
        self.request('/api/acl',{'networks':[]},self.admin)
        self.assertEqual(self.request('/api/backups/trigger',payload,extra_headers=headers)[0],403)
        self.request('/api/acl',{'networks':['127.0.0.1']},self.admin)
        self.request('/api/backups/keys/revoke',{'id':self.key['id']},self.admin)
        self.assertEqual(self.request('/api/backups/trigger',payload,extra_headers=headers)[0],401)

    def test_complete_curl_transfer_and_ambiguous_upload_retry(self):
        self.ambiguous=True
        with self.assertRaises(backMan.TransferError):
            backMan.run(self.config_path)
        self.assertEqual(self.upload_count,1)
        self.assertEqual(len(backups.listing(server.DB)),1)
        state_path=Path(self.temp.name)/'work/state.json'
        pending=backMan.load_json(state_path)['hosts']['outhman']['pending']
        self.assertIsNotNone(pending)
        # Recovery lists the existing CSO path, then verifies it without uploading/triggering again.
        backMan.run(self.config_path)
        self.assertEqual(self.upload_count,1)
        self.assertEqual(len(backups.listing(server.DB)),1)
        state=backMan.load_json(state_path)
        self.assertIsNone(state['hosts']['outhman']['pending'])
        self.assertIsNone(state['cycle'])
        last=state['hosts']['outhman']['last_success']
        self.assertEqual(last['backup']['sha256'],hashlib.sha256(self.files[1]['bytes']).hexdigest())
        self.assertEqual(last['cso_file_id'],1)
        self.assertNotIn(self.key['api_key'],state_path.read_text())
        self.assertNotIn('test-cso-secret',state_path.read_text())
        self.assertTrue(self.files[1]['bytes'].startswith(backups.MAGIC))

    def test_checksum_failure_stays_pending_until_verified(self):
        self.corrupt_download=True
        with self.assertRaisesRegex(backMan.TransferError,'checksum'):
            backMan.run(self.config_path)
        self.assertIsNotNone(backMan.load_json(Path(self.temp.name)/'work/state.json')['hosts']['outhman']['pending'])
        self.corrupt_download=False
        backMan.run(self.config_path)
        self.assertEqual(self.upload_count,1)
        self.assertEqual(len(backups.listing(server.DB)),1)

    def test_partial_multi_host_cycle_does_not_repeat_completed_hosts(self):
        self.config['hosts'].append(dict(self.config['hosts'][0],name='second-host'))
        self.config_path.write_text(json.dumps(self.config))
        self.ambiguous_on=2
        with self.assertRaises(backMan.TransferError):
            backMan.run(self.config_path)
        self.assertEqual(self.upload_count,2)
        self.assertEqual(len(backups.listing(server.DB)),2)
        backMan.run(self.config_path)
        self.assertEqual(self.upload_count,2)
        self.assertEqual(len(backups.listing(server.DB)),2)
        self.assertIsNone(backMan.load_json(Path(self.temp.name)/'work/state.json')['cycle'])

    def test_url_validation_and_runner_calendar(self):
        clean = backMan.validate_metadata({'id':'a'*32,'size':1,'sha256':'b'*64,'passphrase':'not-for-state'})
        self.assertNotIn('passphrase',clean)
        with self.assertRaises(backMan.TransferError):backMan.base_url('http://example.com')
        with self.assertRaises(backMan.TransferError):backMan.base_url('https://user:password@example.com')
        stamp=lambda value:datetime.fromisoformat(value).timestamp()
        self.assertEqual(backMan_runner.next_run({'frequency':'daily','time':'01:00','timezone':'America/Chicago'},stamp('2026-11-08T00:00:00-06:00')),stamp('2026-11-08T01:00:00-06:00'))
        self.assertEqual(backMan_runner.next_run({'frequency':'weekly','time':'01:00','timezone':'America/Chicago','weekdays':[5]},stamp('2026-11-08T00:00:00-06:00')),stamp('2026-11-14T01:00:00-06:00'))
        self.assertEqual(backMan_runner.next_run({'frequency':'monthly','time':'01:00','timezone':'America/Chicago','day_of_month':31},stamp('2026-02-01T00:00:00-06:00')),stamp('2026-02-28T01:00:00-06:00'))


if __name__=='__main__':unittest.main()
