const { listApps } = require('./dist/store');
(async () => {
  const apps = await listApps();
  for (const app of apps) {
    console.log('app', app.id, app.name);
    console.log('  resource', app.resource_uri);
    console.log('  mcp', app.mcp_server_ids);
    console.log('  meta name', app.meta_info?.chatAppMeta?.name);
  }
})();
