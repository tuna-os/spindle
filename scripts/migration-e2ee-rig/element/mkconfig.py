import json, sys
webroot, hs = sys.argv[1], sys.argv[2]
c = json.load(open(f"{webroot}/config.sample.json"))
c["default_server_config"] = {"m.homeserver": {"base_url": hs, "server_name": "reilly.asia"}}
c["disable_custom_urls"] = True
c["disable_guests"] = True
for k in ("integrations_ui_url", "integrations_rest_url", "integrations_widgets_urls", "posthog", "map_style_url", "bug_report_endpoint_url"):
    c.pop(k, None)
c["setting_defaults"] = {**c.get("setting_defaults", {}), "UIFeature.registration": False}
json.dump(c, open(f"{webroot}/config.json", "w"), indent=1)
print(json.dumps(c["default_server_config"]))
