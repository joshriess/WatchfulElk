# elk-alerts

This program queries the KSU Cyber Defense Club Elastic Stack for alerts and sends them to Slack.

## How to configure what the Slack alert looks like
To change what is displayed in the Slack alert, you must simply include the name of the variable you want to display, surrounded by dollar signs ($), in the description of the rule

### Example:
If I would like to include the username and agent hostname from the alert in the Slack message, I would include the following in the rule description:
> $user.name$ $agent.hostname$

By default, all Slack alerts will include the timestamp of the alert and the name of the rule that created the alert.

Note: You may include an actual description for your rule, this program will only look for things that are surrounded by the dollar signs.