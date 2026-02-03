---
layout: projects-home
title: Projects
subtitle: My Personal & Professional Projects
---

Here you'll find my personal and professional projects. From security research labs to side projects, each represents my learning journey and technical interests.

Feel free to explore and reach out if you'd like to collaborate or discuss any of these projects!

## Featured Projects
{% for project in site.projects %}
### [{{ project.title }}]({{ project.url }})
{{ project.subtitle }}

{% endfor %}
