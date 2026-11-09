import json
from pathlib import Path
import tempfile
import threading
import unittest

import backups
import server
import test_server


class LogAPI(unittest.TestCase):
    request = test_server.Flows.request

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = server.DB
        server.DB = Path(self.temp.name) / 'test.db'
        server.initialize()
        self.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        _, _, cookie = self.request('/api/login', {'username':'admin@admin.com','password':'pass123'})
        _, _, self.admin = self.request('/api/change-credentials', {'username':'log-admin','password':'PrivatePassword123!'}, cookie)
        self.request('/api/acl', {'networks':['127.0.0.1']}, self.admin)
        _, self.app_a, _ = self.request('/api/apps', {'name':'App A'}, self.admin)
        _, self.app_b, _ = self.request('/api/apps', {'name':'App B'}, self.admin)
        _, self.key_a, _ = self.request('/api/logs/keys', {'name':'App A collector','app_id':self.app_a['app_id']}, self.admin)
        _, self.key_all, _ = self.request('/api/logs/keys', {'name':'Central collector','app_id':'*'}, self.admin)

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.temp.cleanup()
        server.DB = self.old_db

    def get_logs(self, query='', key=None):
        return self.request('/api/logs'+query, extra_headers={'Authorization':'Bearer '+(key or self.key_a)['api_key']})

    def test_scope_pagination_and_read_only_permissions(self):
        with server.connect() as db:
            for app in (self.app_a['app_id'], self.app_b['app_id'], self.app_a['app_id']):
                db.execute('INSERT INTO events(action,username,ip,browser,created_at,app_id) VALUES(?,?,?,?,?,?)', ('Verified app login','person','127.0.0.1','test',100,app))
        status, page, _ = self.get_logs('?stream=activity&limit=1')
        self.assertEqual(status,200)
        self.assertEqual(len(page['entries']),1)
        self.assertTrue(page['has_more'])
        self.assertEqual(page['entries'][0]['app_id'],self.app_a['app_id'])
        _, second, _ = self.get_logs(f"?stream=activity&limit=1&after={page['next_after']}&epoch={page['epoch']}")
        self.assertEqual(len(second['entries']),1)
        self.assertGreater(second['entries'][0]['id'],page['entries'][0]['id'])
        self.assertFalse(second['has_more'])
        self.assertEqual(self.get_logs(f"?after={second['next_after']}")[1]['entries'],[])
        all_rows=self.get_logs(key=self.key_all)[1]['entries']
        self.assertTrue(any(r['app_id']==self.app_b['app_id'] for r in all_rows))
        self.assertTrue(any(r['app_id'] is None for r in all_rows))
        self.assertEqual(self.get_logs('?app_id='+self.app_b['app_id'])[0],400)
        for query in ('?limit=0','?limit=501','?after=-1','?stream=unknown','?limit=2&limit=3','?after=abc'):
            self.assertEqual(self.get_logs(query)[0],400)
        self.assertEqual(self.get_logs('?after=999999999')[0],409)
        self.assertEqual(self.request('/api/logs')[0],401)
        headers={'Authorization':'Bearer '+self.key_a['api_key']}
        self.assertEqual(self.request('/api/logs/keys', extra_headers=headers)[0],403)
        self.assertEqual(self.request('/api/logs/keys', {'name':'Escalate','app_id':'*'}, extra_headers=headers)[0],401)
        self.assertEqual(self.request('/api/backups', extra_headers=headers)[0],401)
        listed=self.request('/api/logs/keys',cookie=self.admin)[1]
        self.assertNotIn(self.key_a['api_key'],json.dumps(listed))
        self.assertNotIn('hash',listed['keys'][0])
        self.request('/api/logs/keys/revoke',{'id':self.key_a['id']},self.admin)
        self.assertEqual(self.get_logs()[0],401)

    def test_authenticated_attribution_acl_and_app_revocation(self):
        # Valid app auth but invalid user credentials is still attributable to the app.
        self.assertEqual(self.request('/api/v1/enroll',{'username':'unknown','password':'bad','code':'123456'},app=self.app_a)[0],401)
        # Wrong credentials claiming App B must remain unscoped, preventing false attribution.
        self.request('/api/v1/enroll',{'username':'unknown'}, app=dict(self.app_b,app_secret='wrong'))
        request_page=self.get_logs('?stream=requests')[1]
        self.assertTrue(request_page['entries'])
        self.assertTrue(all(r['app_id']==self.app_a['app_id'] for r in request_page['entries']))
        self.assertTrue(any(r['status']==401 for r in request_page['entries']))
        activity=self.get_logs()[1]['entries']
        self.assertTrue(any(r['app_id']==self.app_a['app_id'] for r in activity))
        self.assertTrue(any(r['app_id'] is None for r in self.get_logs('?stream=requests',key=self.key_all)[1]['entries']))
        self.request('/api/acl',{'networks':[]},self.admin)
        self.assertEqual(self.get_logs()[0],403)
        self.request('/api/acl',{'networks':['127.0.0.1']},self.admin)
        self.request('/api/apps/revoke',{'app_id':self.app_a['app_id']},self.admin)
        self.assertEqual(self.get_logs()[0],403)
        self.assertEqual(self.get_logs(key=self.key_all)[0],200)

    def test_restore_epoch_and_retention_gap(self):
        old_epoch=self.get_logs(key=self.key_all)[1]['epoch']
        created=backups.create(server.DB,'private log test passphrase')
        encrypted=backups.path_for(server.DB,created['id']).read_bytes()
        backups.restore(server.DB,encrypted,'private log test passphrase')
        status,result,_=self.get_logs('?epoch='+old_epoch,key=self.key_all)
        self.assertEqual(status,409)
        self.assertTrue(result['reset_required'])
        self.assertNotEqual(old_epoch,result['epoch'])
        with server.connect() as db:
            db.execute('INSERT INTO api_requests(id,created_at,method,endpoint,ip,client,status,app_id) VALUES(100,1,?,?,?,?,?,?)',('POST','/api/v1/enroll','127.0.0.1','test',200,self.app_a['app_id']))
        result=self.get_logs('?stream=requests&after=1')[1]
        self.assertTrue(result['retention_gap'])
        self.assertEqual(result['oldest_available_id'],100)
        self.assertNotIn('Authorization',json.dumps(result))


if __name__=='__main__':
    unittest.main()
