KISSY.Editor.add("resize",function(a){var c=KISSY,o=c.Node;c.use("dd",function(){var p=c.Draggable,q=a.statusDiv,e=a.textarea,b=new o("<div class='ke-resizer'>"),f=a.cfg.pluginConfig.resize||{};f=f.direction||["x","y"];b.appendTo(q);a.on("maximizeWindow",function(){b.css("display","none")});a.on("restoreWindow",function(){b.css("display","")});b._4e_unselectable();var g=new p({node:b}),h=0,i=0,j=0,k=0,l=a.wrap,m=a.editorWrap;g.on("dragstart",function(){h=l.height();i=m.width();j=e.height();k=e.width()});
g.on("drag",function(d){var n=d.left-this.startNodePos.left;d=d.top-this.startNodePos.top;if(c.inArray("y",f)){l.height(h+d);e.height(j+d)}if(c.inArray("x",f)){m.width(i+n);e.width(k+n)}});a.on("destroy",function(){g.destroy();b.remove()})})},{attach:false});
