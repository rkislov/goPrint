#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
"""Render public Markdown manuals with actual UI screenshots (ReportLab, Pillow)."""
from pathlib import Path
import re, textwrap
from xml.sax.saxutils import escape
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, Preformatted, KeepTogether
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from PIL import Image as PILImage
ROOT = Path(__file__).resolve().parents[1]
font_candidates = [Path('/System/Library/Fonts/Supplemental/Arial.ttf'),Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')]
font = next((p for p in font_candidates if p.exists()),None)
if font is None: raise SystemExit('Install Arial or DejaVu Sans to render Cyrillic')
bold = font.with_name('Arial Bold.ttf') if font.name=='Arial.ttf' else font.with_name('DejaVuSans-Bold.ttf')
pdfmetrics.registerFont(TTFont('Manual',str(font)))
pdfmetrics.registerFont(TTFont('ManualBold',str(bold)))
pdfmetrics.registerFontFamily('Manual',normal='Manual',bold='ManualBold',italic='Manual',boldItalic='ManualBold')
styles = {
 'body':ParagraphStyle('body',fontName='Manual',fontSize=9.7,leading=13.4,spaceAfter=8,textColor=HexColor('#233e38')),
 'title':ParagraphStyle('title',fontName='ManualBold',fontSize=29,leading=36,spaceAfter=24,textColor=HexColor('#113e34')),
 'h2':ParagraphStyle('h2',fontName='ManualBold',fontSize=20,leading=25,spaceAfter=18,textColor=HexColor('#113e34')),
 'caption':ParagraphStyle('caption',fontName='Manual',fontSize=8,leading=11,spaceAfter=12,textColor=HexColor('#62756e')),
 'code':ParagraphStyle('code',fontName='Manual',fontSize=7.5,leading=11,backColor=HexColor('#edf3ef'),borderPadding=8,spaceBefore=5,spaceAfter=14),
}
def inline(t):
 t=escape(t)
 t=re.sub(r'\*\*([^*]+)\*\*',r'<b>\1</b>',t)
 t = re.sub(r'\[([^]]+)\]\((https?://[^)]+)\)',r'<link href="\2" color="#176e59">\1</link>',t)
 return re.sub(r'`([^`]+)`',r'<b>\1</b>',t)
def footer(c,doc):
 c.saveState();w,h=doc.pagesize
 c.setStrokeColor(HexColor('#d4e1d9'));c.line(44,40,w-44,40)
 c.setFont('Manual',8);c.setFillColor(HexColor('#62756e'))
 c.drawString(44,26,'GoPrint · v0.2.0-beta.1 · 19.10.2026')
 c.drawRightString(w-44,26,str(doc.page));c.restoreState()
class ManualDocument(SimpleDocTemplate):
 def afterFlowable(self, flowable):
  if isinstance(flowable, Paragraph) and flowable.style.name == 'h2':
   key = 'section-' + str(getattr(self, '_section_count', 0))
   self._section_count = getattr(self, '_section_count', 0) + 1
   self.canv.bookmarkPage(key)
   self.canv.addOutlineEntry(flowable.getPlainText(), key, level=0)

def render(source,target):
 story=[];lines=source.read_text().splitlines();i=0
 while i<len(lines):
  line=lines[i];i+=1
  if not line.strip():continue
  if line.startswith('# '):
   story.extend([Spacer(1,48),Paragraph('G / GOPRINT',styles['caption']),Paragraph(inline(line[2:]),styles['title'])]);continue
  if line.startswith('## '):
   story.extend([PageBreak(),Paragraph(inline(line[3:]),styles['h2'])]);continue
  if line.lstrip().startswith('```'):
   language=line.strip()[3:].strip()
   code=[]
   while i<len(lines) and not lines[i].lstrip().startswith('```'):code.append(lines[i]);i+=1
   i+=1
   # Keep wrapped shell/PowerShell/systemd commands copyable.
   formatted=[]
   for original in code:
    parts=textwrap.wrap(original,width=88,replace_whitespace=False,drop_whitespace=True,break_long_words=False,break_on_hyphens=False) or ['']
    continuation=' `\n  ' if language in ('powershell','ps1') else ' \\\n  ' if language in ('sh','bash','ini') else '\n'
    if original.lstrip().startswith('#'):
     formatted.append('\n'.join(parts[:1]+['# '+x.lstrip('# ') for x in parts[1:]]))
    else:
     formatted.append(continuation.join(parts))
   code='\n'.join(formatted)
   story.append(Preformatted(escape(code),styles['code']));continue
  image=re.match(r'!\[(.*?)\]\((.*?)\)',line)
  if image:
   caption,path=image.groups();p=source.parent/path
   with PILImage.open(p) as im: iw,ih=im.size
   max_height=240 if p.name=='18-sso-keytab.png' else 250 if p.name=='12-katusha.jpg' else 310
   scale=min(507/iw,max_height/ih)
   img=Image(str(p),width=iw*scale,height=ih*scale);img.hAlign='LEFT'
   story.append(KeepTogether([img,Spacer(1,6),Paragraph(escape(caption)+'. Демонстрационный стенд.',styles['caption'])]));continue
  para=[line]
  while i<len(lines) and lines[i].strip() and not lines[i].lstrip().startswith(('#','```','![')):
   para.append(lines[i]);i+=1
  story.append(Paragraph('<br/>'.join(inline(s) for s in para),styles['body']))
 target.parent.mkdir(parents=True,exist_ok=True)
 doc=ManualDocument(str(target),pagesize=(595.28,841.89),leftMargin=44,rightMargin=44,topMargin=44,bottomMargin=55,title=source.read_text().splitlines()[0][2:],author='Кислов Роман Сергеевич',pageCompression=1)
 doc.build(story,onFirstPage=footer,onLaterPages=footer)
for src,name in [('ADMINISTRATOR.md','GoPrint-Administrator.pdf'),('USER.md','GoPrint-User.pdf')]:
 render(ROOT/'docs'/src,ROOT/'output/pdf'/name)
 print(name)
