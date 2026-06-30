    // ===== THUMBNAILS MODE =====
    if (p.carouselMode === 'thumbnails') {
      const caw = p.contentAreaWidth || 'auto';
      const cawUnit = p.contentAreaWidthUnit || 'px';
      const cah = p.contentAreaHeight || 'auto';
      const cahUnit = p.contentAreaHeightUnit || 'px';
      const bigContainer = document.createElement('div');
      bigContainer.style.flex = '1';
      bigContainer.style.position = 'relative';
      bigContainer.style.overflow = 'visible';
      bigContainer.style.minHeight = '200px';
      if (caw !== 'auto') bigContainer.style.width = isNaN(Number(caw)) ? caw : caw + cawUnit;
      if (cah !== 'auto') bigContainer.style.height = isNaN(Number(cah)) ? cah : cah + cahUnit;
      const bigSlide = document.createElement('div');
      bigSlide.style.width = '100%';
      bigSlide.style.height = '100%';
      bigSlide.style.display = 'flex';
      bigSlide.style.justifyContent = slideMain;
      bigSlide.style.alignItems = slideCross;
      bigSlide.style.overflow = 'visible';
      bigSlide.style.padding = '2px';
      const childContent = children[currentIndex] ? renderNodeDOM(children[currentIndex]) : createPlaceholder(node.type);
      childContent.style.overflow = 'visible';
      // --- FIX: Force Image/Video to stretch full width of big slide ---
      const childNode = children[currentIndex];
      if (childNode && (childNode.type === 'Image' || childNode.type === 'Video')) {
        const childWidth = childNode.properties.width;
        const childWidthUnit = childNode.properties.widthUnit;
        const isAutoOrPercent = (childWidth === 'auto') || (childWidthUnit === '%') || (childWidthUnit === 'px' && childWidth === '100%');
        if (isAutoOrPercent) {
          childContent.style.display = 'block';
          childContent.style.width = '100%';
          childContent.style.boxSizing = 'border-box';
          childContent.style.maxWidth = 'none';
          const innerMedia = childContent.querySelector('img, video');
          if (innerMedia) {
            innerMedia.style.width = '100%';
            innerMedia.style.height = 'auto';
            innerMedia.style.display = 'block';
            innerMedia.style.maxWidth = 'none';
          }
        }
      }
      // ----------------------------------------------------------------
      bigSlide.appendChild(childContent);
      bigContainer.appendChild(bigSlide);

      const thumbStrip = document.createElement('div');
      thumbStrip.className = 'carousel-thumbnail-strip';
      const thumbPos = p.thumbnailPosition || 'bottom';
      const thumbAlign = p.thumbnailAlignment || 'center';
      const thumbVertAlign = p.thumbnailVerticalAlignment || 'center';
      const thumbW = parseFloat(p.thumbnailWidth) || 60;
      const thumbH = parseFloat(p.thumbnailHeight) || 60;
      const thumbWUnit = p.thumbnailWidthUnit || 'px';
      const thumbHUnit = p.thumbnailHeightUnit || 'px';
      const thumbGap = parseFloat(p.thumbnailGap) || 8;
      thumbStrip.style.gap = thumbGap + 'px';

      if (thumbPos === 'top' || thumbPos === 'bottom') {
        thumbStrip.style.justifyContent = horizMap[thumbAlign] || 'center';
      } else if (thumbPos === 'left' || thumbPos === 'right') {
        thumbStrip.classList.add('vertical');
        thumbStrip.style.justifyContent = vertMap[thumbVertAlign] || 'center';
      }

      const tBg = getThumbnailBackgroundStyle(node);
      const tBorderC = p.thumbnailBorderColor || '#e2e8f0';
      const tBorderW = parseFloat(p.thumbnailBorderWidth) || 2;
      const tBorderStyle = p.thumbnailBorderStyle || 'solid';
      const tBorderSide = p.thumbnailBorderSide || 'all';
      const tRad = p.thumbnailBorderRadius || { tl:4, tr:4, bl:4, br:4 };
      const selBorderC = p.selectedThumbnailBorderColor || '#3b82f6';
      const selBorderW = parseFloat(p.selectedThumbnailBorderWidth) || 3;
      const selBorderStyle = p.selectedThumbnailBorderStyle || 'solid';
      const selBg = p.selectedThumbnailBgColor || '#ffffff';
      const contentScale = parseFloat(p.thumbnailContentScale) || 0;

      function createThumbnail(child, idx) {
        const isActive = idx === currentIndex;
        const thumb = document.createElement('div');
        thumb.className = 'carousel-thumbnail' + (isActive ? ' active' : '');
        thumb.style.width = thumbW + thumbWUnit;
        thumb.style.height = thumbH + thumbHUnit;
        thumb.style.borderRadius = radiusToCss(tRad);
        thumb.style.background = isActive ? selBg : tBg;
        const borderW = isActive ? selBorderW : tBorderW;
        const borderC = isActive ? selBorderC : tBorderC;
        const borderStyle = isActive ? selBorderStyle : tBorderStyle;
        if (borderW > 0 && borderStyle !== 'none') {
          const bVal = borderW + 'px ' + borderStyle + ' ' + borderC;
          if (tBorderSide === 'all') { thumb.style.border = bVal; }
          else { const sm = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sm[tBorderSide]) thumb.style[sm[tBorderSide]] = bVal; }
        } else { thumb.style.border = '2px solid transparent'; }
        thumb.style.position = 'relative';
        thumb.style.overflow = 'hidden';

        const childClone = renderNodeDOM(child);
        const badges = childClone.querySelectorAll('.node-badge');
        badges.forEach(b => b.remove());

        const childProps = child.properties;
        const childWidth = childProps.width || 'auto';
        const childWidthUnit = childProps.widthUnit || 'px';
        const isResponsive = childWidth === 'auto' || childWidthUnit === '%' || (childWidthUnit === 'px' && childWidth === '100%');

        if (isResponsive) {
          childClone.style.display = 'block';
          childClone.style.width = '100%';
          childClone.style.height = 'auto';
          childClone.style.boxSizing = 'border-box';
          childClone.style.maxWidth = 'none';
          const innerMedia = childClone.querySelector('img, video');
          if (innerMedia) {
            innerMedia.style.width = '100%';
            innerMedia.style.height = 'auto';
            innerMedia.style.display = 'block';
            innerMedia.style.maxWidth = 'none';
          }
        }

        thumb.appendChild(childClone);
        childClone.offsetHeight; // force reflow
        const naturalWidth = childClone.offsetWidth;
        const naturalHeight = childClone.offsetHeight;
        thumb.removeChild(childClone);

        let scale;
        if (contentScale > 0) {
          scale = contentScale;
        } else if (isResponsive) {
          scale = 1; // already fills the thumbnail
        } else {
          const scaleW = thumbW / (naturalWidth || 1);
          const scaleH = thumbH / (naturalHeight || 1);
          scale = Math.min(scaleW, scaleH);
        }

        childClone.style.transform = `scale(${scale})`;
        childClone.style.transformOrigin = 'top left';
        childClone.style.position = 'absolute';
        childClone.style.top = '0';
        childClone.style.left = '0';
        childClone.style.overflow = 'visible';

        if (isResponsive) {
          childClone.style.width = '100%';
          childClone.style.boxSizing = 'border-box';
          childClone.style.maxWidth = 'none';
          const innerMedia2 = childClone.querySelector('img, video');
          if (innerMedia2) {
            innerMedia2.style.width = '100%';
            innerMedia2.style.display = 'block';
            innerMedia2.style.maxWidth = 'none';
          }
        } else {
          childClone.style.width = naturalWidth + 'px';
        }

        thumb.appendChild(childClone);
        thumb.addEventListener('click', (e) => { e.stopPropagation(); goToSlide(idx); });
        return thumb;
      }

      children.forEach((child, idx) => {
        const thumb = createThumbnail(child, idx);
        thumbStrip.appendChild(thumb);
      });

      if (thumbPos === 'top') {
        container.style.display = 'flex'; container.style.flexDirection = 'column-reverse';
        container.appendChild(bigContainer); container.appendChild(thumbStrip);
      } else if (thumbPos === 'bottom') {
        container.style.display = 'flex'; container.style.flexDirection = 'column';
        container.appendChild(bigContainer); container.appendChild(thumbStrip);
      } else if (thumbPos === 'left') {
        container.style.display = 'flex'; container.style.flexDirection = 'row';
        container.appendChild(thumbStrip); container.appendChild(bigContainer);
      } else if (thumbPos === 'right') {
        container.style.display = 'flex'; container.style.flexDirection = 'row-reverse';
        container.appendChild(thumbStrip); container.appendChild(bigContainer);
      }

      if (p.showArrows) renderArrows();
      buildCarouselInterval();
      const badge = document.createElement('div'); badge.className = 'node-badge';
      badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
      if (!(structureLabelsVisible || node.id === selectedId)) badge.classList.add('hidden-label');
      container.appendChild(badge);
      return container;
    }

    // ===== STANDARD MODE =====
    if (p.carouselMode === 'standard' && totalSlides > 1) {
      const activeW = p.activeWidth || 80;
      const activeWUnit = p.activeWidthUnit || '%';
      const sideW = p.sideWidth || 60;
      const sideWUnit = p.sideWidthUnit || '%';
      container.style.display = 'flex'; container.style.alignItems = 'center'; container.style.justifyContent = 'center'; container.style.gap = toPx(p.slideSpacing || '16');
      function renderStandardSlide(child, idx) {
        const slideWrapper = document.createElement('div');
        slideWrapper.style.transition = `all ${p.speed}ms ease`;
        slideWrapper.style.cursor = 'pointer';
        slideWrapper.style.overflow = 'visible';
        const isActive = idx === currentIndex;
        slideWrapper.style.width = isActive ? (activeW + activeWUnit) : (sideW + sideWUnit);
        slideWrapper.style.height = isActive ? (p.activeHeight !== 'auto' ? toPx(p.activeHeight) : '100%') : (p.sideHeight !== 'auto' ? toPx(p.sideHeight) : '100%');
        slideWrapper.style.opacity = isActive ? (p.activeOpacity || 1) : (p.sideOpacity || 0.6);
        slideWrapper.style.transform = isActive ? `scale(${p.activeScale || 1})` : `scale(${p.sideScale || 0.8})`;
        slideWrapper.style.flexShrink = '0';
        slideWrapper.style.padding = '2px';
        applySlideAlignment(slideWrapper);
        const childDOM = renderNodeDOM(child);
        childDOM.style.overflow = 'visible';
        slideWrapper.appendChild(childDOM);
        slideWrapper.addEventListener('click', () => goToSlide(idx));
        return slideWrapper;
      }
      const prevIndex = (currentIndex-1+totalSlides)%totalSlides, nextIndex = (currentIndex+1)%totalSlides;
      container.appendChild(renderStandardSlide(children[prevIndex], prevIndex));
      container.appendChild(renderStandardSlide(children[currentIndex], currentIndex));
      container.appendChild(renderStandardSlide(children[nextIndex], nextIndex));
      renderArrows(); renderIndicators();
      buildCarouselInterval();
      const badge = document.createElement('div'); badge.className = 'node-badge';
      badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
      if (!(structureLabelsVisible || node.id === selectedId)) badge.classList.add('hidden-label');
      container.appendChild(badge);
      return container;
    }

    // Fallback (single slide or empty)
    const fallbackDiv = document.createElement('div');
    fallbackDiv.style.display = 'flex'; fallbackDiv.style.justifyContent = 'center'; fallbackDiv.style.alignItems = 'center'; fallbackDiv.style.minHeight = '100px'; fallbackDiv.style.overflow = 'visible'; fallbackDiv.style.padding = '2px';
    if (children.length === 0) fallbackDiv.appendChild(createPlaceholder('Carousel'));
    else { const childDOM = renderNodeDOM(children[0]); childDOM.style.overflow = 'visible'; fallbackDiv.appendChild(childDOM); }
    container.appendChild(fallbackDiv);
    if (p.showArrows) renderArrows();
    if (p.showIndicators) renderIndicators();
    buildCarouselInterval();
    const badge = document.createElement('div'); badge.className = 'node-badge';
    badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
    if (!(structureLabelsVisible || node.id === selectedId)) badge.classList.add('hidden-label');
    container.appendChild(badge);
    return container;
  }

  // ==================== TABLE ====================
  function renderTable(node) {
    const p = node.properties;
    const columns = JSON.parse(p.columns || '[]');
    const rows = JSON.parse(p.rows || '[]');
    const tableWrapper = document.createElement('div');
    tableWrapper.className = 'table-wrapper';
    tableWrapper.setAttribute('data-node-id', node.id);
    tableWrapper.setAttribute('data-type', node.type);
    tableWrapper.style.cursor = 'pointer';
    tableWrapper.style.position = 'relative';
    tableWrapper.style.display = 'inline-block';
    const mainBorderW = (p.borderWidth !== undefined) ? parseFloat(p.borderWidth) : 0;
    const mainBorderStyle = p.borderStyle || 'solid';
    const mainBorderColor = p.borderColor || '#000000';
    const mainBorderSide = p.borderSide || 'all';
    if (mainBorderW > 0 && mainBorderStyle !== 'none') {
      const borderVal = `${mainBorderW}px ${mainBorderStyle} ${mainBorderColor}`;
      if (mainBorderSide === 'all') { tableWrapper.style.border = borderVal; }
      else { tableWrapper.style.border = 'none'; const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[mainBorderSide]) tableWrapper.style[sideMap[mainBorderSide]] = borderVal; }
    } else { tableWrapper.style.border = 'none'; }
    const bgStyle = getBackgroundStyle(node);
    let shadowCss = 'none';
    if (p.shadowColor && p.shadowBlur !== undefined) { shadowCss = `${p.shadowOffsetX}px ${p.shadowOffsetY}px ${p.shadowBlur}px ${p.shadowSpread}px ${p.shadowColor}`; }
    const widthVal = p.width === 'auto' ? 'auto' : (isNaN(Number(p.width)) ? p.width : p.width + (p.widthUnit || 'px'));
    const heightVal = p.height === 'auto' ? 'auto' : (isNaN(Number(p.height)) ? p.height : p.height + (p.heightUnit || 'px'));
    Object.assign(tableWrapper.style, { background: bgStyle, padding: dirToCss(p.padding), margin: dirToCss(p.margin), borderRadius: radiusToCss(p.borderRadius), width: widthVal, height: heightVal, minWidth: p.minWidth ? toPx(p.minWidth) : '', minHeight: p.minHeight ? toPx(p.minHeight) : '', maxWidth: p.maxWidth ? toPx(p.maxWidth) : '', maxHeight: p.maxHeight ? toPx(p.maxHeight) : '', boxShadow: shadowCss, opacity: p.opacity !== undefined ? Number(p.opacity) : 1, transform: p.rotation ? `rotate(${p.rotation}deg)` : 'none', boxSizing: 'border-box' });
    const hasAnyRadius = (p.borderRadius && (p.borderRadius.tl > 0 || p.borderRadius.tr > 0 || p.borderRadius.bl > 0 || p.borderRadius.br > 0));
    if (hasAnyRadius) { tableWrapper.style.overflow = 'hidden'; }
    const table = document.createElement('table');
    const tablePad = p.tablePadding || { top:0, right:0, bottom:0, left:0 };
    table.style.padding = `${tablePad.top}px ${tablePad.right}px ${tablePad.bottom}px ${tablePad.left}px`;
    table.style.width = '100%';
    const tbW = parseFloat(p.tableBorderWidth) || 0;
    const tbStyle = p.tableBorderStyle || 'solid';
    const tbColor = p.tableBorderColor || '#e2e8f0';
    const tbSide = p.tableBorderSide || 'all';
    if (tbW > 0 && tbStyle && tbStyle !== 'none') {
      const borderVal = `${tbW}px ${tbStyle} ${tbColor}`;
      if (tbSide === 'all') { table.style.border = borderVal; }
      else { table.style.border = 'none'; const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[tbSide]) table.style[sideMap[tbSide]] = borderVal; }
    } else { table.style.border = 'none'; }
    let cellSpacingCss = '0'; const cs = p.cellSpacing; if (cs !== undefined && cs !== null && cs !== '') { cellSpacingCss = isNaN(Number(cs)) ? cs : Number(cs) + 'px'; }
    Object.assign(table.style, { borderCollapse: 'separate', borderSpacing: cellSpacingCss, boxSizing: 'border-box' });
    const thead = document.createElement('thead'); const headerRow = document.createElement('tr'); const sortStates = JSON.parse(p.sortStates || '{}'); const headerPad = p.headerPadding || { top:0, right:0, bottom:0, left:0 }; const rowPad = p.rowPadding || { top:0, right:0, bottom:0, left:0 };
    const headerRadius = p.headerBorderRadius ? radiusToCss(p.headerBorderRadius) : '0'; const rowRadius = p.rowBorderRadius ? radiusToCss(p.rowBorderRadius) : '0';
    columns.forEach((col, colIdx) => { const th = document.createElement('th'); th.textContent = col; applyTextStyle(th, p, 'header'); th.style.padding = `${headerPad.top}px ${headerPad.right}px ${headerPad.bottom}px ${headerPad.left}px`; th.style.background = p.headerBgColor; th.style.border = 'none'; th.style.borderRadius = headerRadius; th.style.position = 'relative';
      if (p.sortable) { const sortIcon = document.createElement('i'); const currentSort = sortStates[colIdx] || null; if (currentSort === 'asc') sortIcon.className = 'fas fa-sort-up'; else if (currentSort === 'desc') sortIcon.className = 'fas fa-sort-down'; else sortIcon.className = 'fas fa-sort'; sortIcon.style.marginLeft = '4px'; sortIcon.style.fontSize = '0.7rem'; sortIcon.style.visibility = currentSort ? 'visible' : 'hidden'; sortIcon.style.cursor = 'pointer'; th.appendChild(sortIcon); th.addEventListener('mouseenter', () => { if (!sortStates[colIdx]) sortIcon.style.visibility = 'visible'; }); th.addEventListener('mouseleave', () => { if (!sortStates[colIdx]) sortIcon.style.visibility = 'hidden'; }); sortIcon.addEventListener('click', (e) => { e.stopPropagation(); const newSortStates = {}; let newDir; if (!sortStates[colIdx]) newDir = 'asc'; else if (sortStates[colIdx] === 'asc') newDir = 'desc'; else newDir = null; if (newDir) { newSortStates[colIdx] = newDir; sortTableByColumn(node, colIdx, newDir); } else { sortTableByColumn(node, colIdx, null); } updateNodeProp(node.id, 'sortStates', JSON.stringify(newSortStates)); }); } headerRow.appendChild(th); });
    thead.appendChild(headerRow); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    rows.forEach((row, rowIdx) => { const tr = document.createElement('tr'); row.forEach((cell, colIdx) => { const td = document.createElement('td'); td.textContent = cell; applyTextStyle(td, p, 'row'); td.style.padding = `${rowPad.top}px ${rowPad.right}px ${rowPad.bottom}px ${rowPad.left}px`; td.style.border = 'none'; td.style.borderRadius = rowRadius; td.setAttribute('contenteditable', 'true'); td.classList.add('table-cell-editable'); td.addEventListener('blur', () => { rows[rowIdx][colIdx] = td.textContent; updateNodeProp(node.id, 'rows', JSON.stringify(rows)); }); td.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); td.blur(); } }); tr.appendChild(td); }); if (rowIdx % 2 === 0) tr.style.background = p.evenRowBgColor || p.rowBgColor; else tr.style.background = p.oddRowBgColor || p.rowBgColor; tbody.appendChild(tr); });
    table.appendChild(tbody); tableWrapper.appendChild(table);
    if (columns.length > 0) { const addColBtn = document.createElement('button'); addColBtn.className = 'table-add-col-btn'; addColBtn.innerHTML = '+'; addColBtn.title = 'Add column'; addColBtn.style.right = '-12px'; addColBtn.style.top = '50%'; addColBtn.style.transform = 'translateY(-50%)'; addColBtn.addEventListener('click', (e) => { e.stopPropagation(); columns.push('Col ' + (columns.length + 1)); rows.forEach(row => row.push('')); updateNodeProp(node.id, 'columns', JSON.stringify(columns)); updateNodeProp(node.id, 'rows', JSON.stringify(rows)); fullRender(); updatePropsPanel(); }); tableWrapper.appendChild(addColBtn); }
    if (rows.length > 0) { const addRowBtn = document.createElement('button'); addRowBtn.className = 'table-add-row-btn'; addRowBtn.innerHTML = '+'; addRowBtn.title = 'Add row'; addRowBtn.style.bottom = '-12px'; addRowBtn.style.left = '50%'; addRowBtn.style.transform = 'translateX(-50%)'; addRowBtn.addEventListener('click', (e) => { e.stopPropagation(); rows.push(new Array(columns.length).fill('')); updateNodeProp(node.id, 'rows', JSON.stringify(rows)); fullRender(); updatePropsPanel(); }); tableWrapper.appendChild(addRowBtn); }
    return tableWrapper;
  }

  function sortTableByColumn(node, colIndex, direction) { let rows = JSON.parse(node.properties.rows || '[]'); if (direction === null) { updateNodeProp(node.id, 'rows', JSON.stringify(rows)); return; } rows.sort((a, b) => { const valA = a[colIndex] || '', valB = b[colIndex] || ''; return direction === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA); }); updateNodeProp(node.id, 'rows', JSON.stringify(rows)); fullRender(); }

  function renderProgressBar(node) {
    const p = node.properties;
    const bgStyle = getBackgroundStyle(node);
    const widthVal = p.width === 'auto' ? 'auto' : (isNaN(Number(p.width)) ? p.width : p.width + (p.widthUnit || 'px'));
    const heightVal = p.height === 'auto' ? 'auto' : (isNaN(Number(p.height)) ? p.height : p.height + (p.heightUnit || 'px'));
    let borderCss = 'none'; if (p.borderWidth > 0 && p.borderStyle && p.borderColor) { if (p.borderSide === 'all') borderCss = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; }
    let shadowCss = 'none'; if (p.shadowColor && p.shadowBlur !== undefined) shadowCss = `${p.shadowOffsetX}px ${p.shadowOffsetY}px ${p.shadowBlur}px ${p.shadowSpread}px ${p.shadowColor}`;

    const wrapper = document.createElement('div');
    Object.assign(wrapper.style, { display: 'block', width: widthVal, height: heightVal, minWidth: p.minWidth ? toPx(p.minWidth) : '', minHeight: p.minHeight ? toPx(p.minHeight) : '', maxWidth: p.maxWidth ? toPx(p.maxWidth) : '', maxHeight: p.maxHeight ? toPx(p.maxHeight) : '', margin: dirToCss(p.margin), opacity: p.opacity !== undefined ? Number(p.opacity) : 1, transform: p.rotation ? `rotate(${p.rotation}deg)` : 'none', position: 'relative' });
    const barContainer = document.createElement('div');
    barContainer.style.background = bgStyle;
    barContainer.style.padding = dirToCss(p.padding);
    barContainer.style.borderRadius = radiusToCss(p.borderRadius);
    barContainer.style.width = '100%';
    barContainer.style.height = '100%';
    barContainer.style.border = borderCss;
    barContainer.style.boxShadow = shadowCss;
    barContainer.style.position = 'relative';
    barContainer.style.overflow = 'hidden';
    barContainer.style.boxSizing = 'border-box';
    if (p.borderWidth > 0 && p.borderStyle && p.borderColor && p.borderSide !== 'all') { barContainer.style.border = 'none'; const borderVal = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[p.borderSide]) barContainer.style[sideMap[p.borderSide]] = borderVal; }

    const bar = document.createElement('div');
    const percentage = Math.min(100, Math.round((p.value / p.max) * 100));
    bar.style.width = percentage + '%'; bar.style.height = '100%';
    bar.style.background = p.striped ? `repeating-linear-gradient(45deg, ${p.barColor}, ${p.barColor} 10px, ${p.barColor}dd 10px, ${p.barColor}dd 20px)` : p.barColor;
    if (p.animated && p.striped) { bar.style.backgroundSize = '200% 100%'; bar.style.animation = 'progress-stripes 2s linear infinite'; }
    bar.style.transition = 'width 0.3s'; bar.style.borderRadius = 'inherit';
    barContainer.appendChild(bar);

    const label = document.createElement('span');
    if (p.showLabel) {
      label.textContent = percentage + '%';
      applyTextStyle(label, p);
      label.style.position = 'absolute';
      label.style.top = '50%';
      if (p.labelPosition === 'inside') {
        label.style.left = '0'; label.style.right = '0'; label.style.width = '100%'; label.style.boxSizing = 'border-box'; label.style.transform = 'translateY(-50%)'; label.style.padding = '0 10px';
        barContainer.appendChild(label);
        wrapper.appendChild(barContainer);
      } else {
        label.style.left = '100%'; label.style.marginLeft = '8px'; label.style.transform = 'translateY(-50%)';
        wrapper.appendChild(barContainer);
        wrapper.appendChild(label);
      }
    } else {
      wrapper.appendChild(barContainer);
    }

    const style = document.createElement('style');
    style.textContent = `@keyframes progress-stripes { 0% { background-position: 0 0; } 100% { background-position: 40px 0; } }`;
    document.head.appendChild(style);
    wrapper.setAttribute('data-node-id', node.id);
    wrapper.setAttribute('data-type', node.type);
    wrapper.style.cursor = 'pointer';
    return wrapper;
  }

  function renderChart(node) {
    const p = node.properties;
    const container = document.createElement('div');
    const bgStyle = getBackgroundStyle(node);
    let borderCss = 'none';
    if (p.borderWidth > 0 && p.borderStyle && p.borderColor) { if (p.borderSide === 'all') borderCss = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; }
    let shadowCss = 'none';
    if (p.shadowColor && p.shadowBlur !== undefined) shadowCss = `${p.shadowOffsetX}px ${p.shadowOffsetY}px ${p.shadowBlur}px ${p.shadowSpread}px ${p.shadowColor}`;
    const widthVal = p.width === 'auto' ? 'auto' : (isNaN(Number(p.width)) ? p.width : p.width + (p.widthUnit || 'px'));
    const heightVal = p.height === 'auto' ? 'auto' : (isNaN(Number(p.height)) ? p.height : p.height + (p.heightUnit || 'px'));
    Object.assign(container.style, { background: bgStyle, padding: dirToCss(p.padding), margin: dirToCss(p.margin), borderRadius: radiusToCss(p.borderRadius), width: widthVal, height: heightVal, minWidth: p.minWidth ? toPx(p.minWidth) : '', minHeight: p.minHeight ? toPx(p.minHeight) : '', maxWidth: p.maxWidth ? toPx(p.maxWidth) : '', maxHeight: p.maxHeight ? toPx(p.maxHeight) : '', border: borderCss, boxShadow: shadowCss, opacity: p.opacity !== undefined ? Number(p.opacity) : 1, transform: p.rotation ? `rotate(${p.rotation}deg)` : 'none', position: 'relative' });
    if (p.borderWidth > 0 && p.borderStyle && p.borderColor && p.borderSide !== 'all') { const borderVal = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; const sideMap = { top: 'borderTop', right: 'borderRight', bottom: 'borderBottom', left: 'borderLeft' }; if (sideMap[p.borderSide]) container.style[sideMap[p.borderSide]] = borderVal; }
    container.setAttribute('data-node-id', node.id); container.setAttribute('data-type', node.type); container.style.cursor = 'pointer';
    if (p.title) { const titleEl = document.createElement('div'); titleEl.textContent = p.title; applyTextStyle(titleEl, p, 'title'); titleEl.style.marginBottom = '8px'; container.appendChild(titleEl); }
    const canvas = document.createElement('canvas');
    canvas.width = 400; canvas.height = 250;
    canvas.style.width = '100%'; canvas.style.height = 'auto';
    container.appendChild(canvas);
    const ctx = canvas.getContext('2d'); const data = JSON.parse(p.data || '[]'); const chartType = p.chartType;

    function drawChartText(ctx, text, x, y, align, prefix, fallbackColor) {
      const ff = p[prefix + 'fontFamily'] || p.fontFamily || 'Inter'; const fs = p[prefix + 'fontSize'] || p.fontSize || '12'; const fw = p[prefix + 'fontWeight'] || p.fontWeight || 'normal'; const fsy = p[prefix + 'fontStyle'] || p.fontStyle || 'normal'; const fc = p[prefix + 'color'] || p.color || fallbackColor; const ta = align; const ls = parseFloat(p[prefix + 'letterSpacing'] || p.letterSpacing || 0); const td = p[prefix + 'textDecoration'] || p.textDecoration || 'none'; const tt = p[prefix + 'textTransform'] || p.textTransform || 'none';
      let displayText = text; if (tt === 'uppercase') displayText = displayText.toUpperCase(); else if (tt === 'lowercase') displayText = displayText.toLowerCase(); else if (tt === 'capitalize') displayText = displayText.replace(/\b\w/g, c => c.toUpperCase());
      ctx.fillStyle = fc; ctx.textBaseline = 'middle'; const fontSizePx = parseFloat(fs); const fontString = `${fsy} ${fw} ${fontSizePx}px ${ff}`; ctx.font = fontString;
      if (ls === 0) { ctx.textAlign = ta; ctx.fillText(displayText, x, y); }
      else { ctx.textAlign = 'left'; const chars = displayText.split(''); const totalWidth = chars.reduce((sum, ch) => sum + ctx.measureText(ch).width + ls, -ls); let startX; if (ta === 'center') startX = x - totalWidth / 2; else if (ta === 'right') startX = x - totalWidth; else startX = x; let currentX = startX; for (const ch of chars) { ctx.fillText(ch, currentX, y); currentX += ctx.measureText(ch).width + ls; } }
      if (td !== 'none') { const metrics = ctx.measureText(displayText); const textWidth = metrics.width; let lineY = y; if (td === 'underline') lineY = y + fontSizePx * 0.3; else if (td === 'line-through') lineY = y; ctx.beginPath(); ctx.strokeStyle = fc; ctx.lineWidth = 1; let lineStartX; if (ta === 'center') lineStartX = x - textWidth / 2; else if (ta === 'right') lineStartX = x - textWidth; else lineStartX = x; ctx.moveTo(lineStartX, lineY); ctx.lineTo(lineStartX + textWidth, lineY); ctx.stroke(); }
    }

    const labelRow = document.createElement('div'); labelRow.style.display = 'flex'; labelRow.style.width = '100%'; labelRow.style.paddingTop = '0'; labelRow.style.marginTop = '-2px'; container.appendChild(labelRow);

    setTimeout(() => {
      const rect = canvas.getBoundingClientRect();
      const targetWidth = rect.width || 400;
      const targetHeight = Math.max(200, rect.height - (p.title ? 30 : 0));
      if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
        canvas.width = targetWidth;
        canvas.height = targetHeight;
      }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const labelMargin = 25;
      const valueLabelMarginTop = 25;
      const valOffX = parseFloat(p.valueOffsetX) || 0;
      const valOffY = parseFloat(p.valueOffsetY) || 0;
      const labelAlign = p.labelTextAlign || 'center';
      const valueAlign = p.valueTextAlign || 'center';
      if (chartType === 'bar') {
        const barCount = data.length;
        const barWidth = (canvas.width / barCount) * 0.6;
        const rawMaxVal = Math.max(...data.map(d => d.value), 1);
        const maxVal = rawMaxVal * 1.05;
        const chartHeight = canvas.height - labelMargin - valueLabelMarginTop;
        data.forEach((d, i) => {
          const barX = (i * (canvas.width / barCount)) + ((canvas.width / barCount) - barWidth) / 2;
          const barHeight = (d.value / maxVal) * chartHeight;
          const barY = valueLabelMarginTop + (chartHeight - barHeight);
          ctx.fillStyle = d.color; ctx.fillRect(barX, barY, barWidth, barHeight);
          if (p.showValues) {
            const valueText = d.value.toString();
            let valX; if (valueAlign === 'left') valX = barX; else if (valueAlign === 'right') valX = barX + barWidth; else valX = barX + barWidth / 2;
            const valueY = barY - 10;
            drawChartText(ctx, valueText, valX + valOffX, valueY + valOffY, valueAlign, 'value', '#0f172a');
          }
          const labelCol = document.createElement('div'); labelCol.style.flex = '1'; labelCol.style.textAlign = labelAlign; labelCol.style.margin = '0'; labelCol.style.padding = '0'; applyTextStyle(labelCol, p, 'label'); labelCol.textContent = d.label; labelRow.appendChild(labelCol);
        });
      } else if (chartType === 'pie') {
        let total = data.reduce((s, d) => s + d.value, 0); let startAngle = 0; const cx = canvas.width / 2, cy = canvas.height / 2; const radius = Math.min(cx, cy) - 30;
        data.forEach(d => { const sliceAngle = (d.value / total) * 2 * Math.PI; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle); ctx.closePath(); ctx.fillStyle = d.color; ctx.fill();
          if (p.showValues) { const midAngle = startAngle + sliceAngle / 2; const labelX = cx + Math.cos(midAngle) * radius * 0.7 + valOffX; const labelY = cy + Math.sin(midAngle) * radius * 0.7 + valOffY; drawChartText(ctx, d.value.toString(), labelX, labelY, 'center', 'value', '#0f172a'); }
          startAngle += sliceAngle; });
        if (p.showLegend) { const legendContainer = document.createElement('div'); legendContainer.style.position = 'absolute'; legendContainer.style.bottom = '5px'; legendContainer.style.left = '50%'; legendContainer.style.transform = 'translateX(-50%)'; legendContainer.style.background = 'rgba(255,255,255,0.9)'; legendContainer.style.padding = '4px 12px'; legendContainer.style.borderRadius = '8px'; legendContainer.style.display = 'flex'; legendContainer.style.gap = '12px'; data.forEach(d => { const item = document.createElement('div'); item.style.display = 'flex'; item.style.alignItems = 'center'; item.style.gap = '4px'; const colorBox = document.createElement('span'); colorBox.style.display = 'inline-block'; colorBox.style.width = '10px'; colorBox.style.height = '10px'; colorBox.style.background = d.color; item.appendChild(colorBox); const labelSpan = document.createElement('span'); labelSpan.textContent = d.label; applyTextStyle(labelSpan, p, 'label'); item.appendChild(labelSpan); legendContainer.appendChild(item); }); container.appendChild(legendContainer); }
      }
      if (chartType !== 'pie' && p.showLegend) { const legendContainer = document.createElement('div'); legendContainer.style.position = 'absolute'; legendContainer.style.top = '10px'; legendContainer.style.right = '10px'; legendContainer.style.background = 'rgba(255,255,255,0.8)'; legendContainer.style.padding = '4px 8px'; legendContainer.style.borderRadius = '4px'; data.forEach(d => { const item = document.createElement('div'); item.style.display = 'flex'; item.style.alignItems = 'center'; item.style.gap = '4px'; const colorBox = document.createElement('span'); colorBox.style.display = 'inline-block'; colorBox.style.width = '10px'; colorBox.style.height = '10px'; colorBox.style.background = d.color; item.appendChild(colorBox); const labelSpan = document.createElement('span'); labelSpan.textContent = d.label; applyTextStyle(labelSpan, p, 'label'); item.appendChild(labelSpan); legendContainer.appendChild(item); }); container.appendChild(legendContainer); }
    }, 100);
    return container;
  }

  function renderCountdown(node) {
    const wrapper = document.createElement('div'); const p = node.properties; const bgStyle = getBackgroundStyle(node); let borderCss = 'none'; if (p.borderWidth > 0 && p.borderStyle && p.borderColor) { if (p.borderSide === 'all') borderCss = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; } let shadowCss = 'none'; if (p.shadowColor && p.shadowBlur !== undefined) shadowCss = `${p.shadowOffsetX}px ${p.shadowOffsetY}px ${p.shadowBlur}px ${p.shadowSpread}px ${p.shadowColor}`; const baseStyle = { background: bgStyle, padding: dirToCss(p.padding), margin: dirToCss(p.margin), borderRadius: radiusToCss(p.borderRadius), width: p.width === 'auto' ? '100%' : (isNaN(Number(p.width)) ? p.width : p.width + (p.widthUnit || 'px')), height: p.height === 'auto' ? 'auto' : (isNaN(Number(p.height)) ? p.height : p.height + (p.heightUnit || 'px')), minWidth: p.minWidth ? toPx(p.minWidth) : '', minHeight: p.minHeight ? toPx(p.minHeight) : '40px', maxWidth: p.maxWidth ? toPx(p.maxWidth) : '', maxHeight: p.maxHeight ? toPx(p.maxHeight) : '', border: borderCss, boxShadow: shadowCss, opacity: p.opacity !== undefined ? Number(p.opacity) : 1, transform: p.rotation ? `rotate(${p.rotation}deg)` : 'none', display: 'flex', flexDirection: 'row', flexWrap: 'wrap' }; if (p.borderWidth > 0 && p.borderStyle && p.borderColor && p.borderSide !== 'all') { const borderVal = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[p.borderSide]) baseStyle[sideMap[p.borderSide]] = borderVal; } Object.assign(wrapper.style, baseStyle); wrapper.style.position = 'relative';
    wrapper.style.justifyContent = p.mainAxisAlignment || 'center';
    const crossMap = { 'flex-start':'flex-start', 'center':'center', 'flex-end':'flex-end', 'stretch':'stretch' };
    wrapper.style.alignItems = crossMap[p.crossAxisAlignment] || 'center';
    const container = document.createElement('div'); container.className = 'countdown-container'; container.style.gap = toPx(p.gap || '20'); container.style.justifyContent = p.mainAxisAlignment || 'center'; container.style.alignItems = p.crossAxisAlignment || 'center';
    const units = [{ key:'days', show:p.showDays, label:p.daysLabel, labelColor:p.daysLabelColor },{ key:'hours', show:p.showHours, label:p.hoursLabel, labelColor:p.hoursLabelColor },{ key:'minutes', show:p.showMinutes, label:p.minutesLabel, labelColor:p.minutesLabelColor },{ key:'seconds', show:p.showSeconds, label:p.secondsLabel, labelColor:p.secondsLabelColor }];
    units.forEach(unit => { if (!unit.show) return; const unitDiv = document.createElement('div'); unitDiv.className = 'countdown-unit'; unitDiv.setAttribute('data-unit', unit.key); const valueSpan = document.createElement('div'); valueSpan.className = 'countdown-value'; valueSpan.textContent = '00'; applyTextStyle(valueSpan, p); const labelSpan = document.createElement('div'); labelSpan.className = 'countdown-label'; labelSpan.textContent = unit.label; const labelPrefix = unit.key + 'Label'; applyTextStyle(labelSpan, p, labelPrefix); labelSpan.style.color = p[labelPrefix+'Color'] || unit.labelColor; unitDiv.appendChild(valueSpan); unitDiv.appendChild(labelSpan); container.appendChild(unitDiv); });
    wrapper.appendChild(container); wrapper.setAttribute('data-node-id', node.id); wrapper.setAttribute('data-type', node.type); wrapper.style.cursor = 'pointer'; return wrapper;
  }

  function renderFlippableCard(node) {
    const p = node.properties; const bgStyle = getBackgroundStyle(node); let borderCss = 'none'; if (p.borderWidth > 0 && p.borderStyle && p.borderColor) { if (p.borderSide === 'all') borderCss = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; } let shadowCss = 'none'; if (p.shadowColor && p.shadowBlur !== undefined) shadowCss = `${p.shadowOffsetX}px ${p.shadowOffsetY}px ${p.shadowBlur}px ${p.shadowSpread}px ${p.shadowColor}`; const widthVal = p.width === 'auto' ? 'auto' : (isNaN(Number(p.width)) ? p.width : p.width + (p.widthUnit || 'px')); const heightVal = p.height === 'auto' ? '400px' : (isNaN(Number(p.height)) ? p.height : p.height + (p.heightUnit || 'px')); const baseStyle = { background: bgStyle, padding: dirToCss(p.padding), margin: dirToCss(p.margin), borderRadius: radiusToCss(p.borderRadius), width: widthVal, height: heightVal, minWidth: p.minWidth ? toPx(p.minWidth) : '', minHeight: p.minHeight ? toPx(p.minHeight) : '', maxWidth: p.maxWidth ? toPx(p.maxWidth) : '', maxHeight: p.maxHeight ? toPx(p.maxHeight) : '', border: borderCss, boxShadow: shadowCss, opacity: p.opacity !== undefined ? Number(p.opacity) : 1, transform: p.rotation ? `rotate(${p.rotation}deg)` : 'none', perspective: '1000px' }; if (p.borderWidth > 0 && p.borderStyle && p.borderColor && p.borderSide !== 'all') { const borderVal = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`; const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[p.borderSide]) baseStyle[sideMap[p.borderSide]] = borderVal; }
    const container = document.createElement('div'); Object.assign(container.style, baseStyle); container.style.position = 'relative'; container.setAttribute('data-node-id', node.id); container.setAttribute('data-type', node.type); container.style.cursor = 'pointer';
    const flipper = document.createElement('div'); flipper.style.width = '100%'; flipper.style.height = '100%'; flipper.style.position = 'relative'; flipper.style.transformStyle = 'preserve-3d'; flipper.style.transition = `transform ${p.animationDuration}ms ${p.animationEasing} ${p.animationDelay}ms`;
    const editSide = p.editSide || 'front';
    const frontCol = node.children && node.children[0] ? node.children[0] : null;
    const backCol = node.children && node.children[1] ? node.children[1] : null;

    if (p.flipDirection === 'vertical') {
      flipper.style.transform = editSide === 'back' ? 'rotateX(180deg)' : 'rotateX(0deg)';
    } else {
      flipper.style.transform = editSide === 'back' ? 'rotateY(180deg)' : 'rotateY(0deg)';
    }

    const frontDiv = document.createElement('div');
    frontDiv.style.position = 'absolute';
    frontDiv.style.width = '100%';
    frontDiv.style.height = '100%';
    frontDiv.style.backfaceVisibility = 'hidden';
    frontDiv.style.overflow = 'visible';
    if (p.flipDirection === 'vertical') frontDiv.style.transform = 'rotateX(0deg)';
    else frontDiv.style.transform = 'rotateY(0deg)';
    frontDiv.style.opacity = editSide === 'back' ? '0' : '1';
    frontDiv.style.pointerEvents = editSide === 'back' ? 'none' : 'auto';
    if (frontCol) frontDiv.appendChild(renderNodeDOM(frontCol));
    else { const ph = createPlaceholder('Column'); ph.innerText = 'Empty Flip Card Front'; frontDiv.appendChild(ph); }

    const backDiv = document.createElement('div');
    backDiv.style.position = 'absolute';
    backDiv.style.width = '100%';
    backDiv.style.height = '100%';
    backDiv.style.backfaceVisibility = 'hidden';
    backDiv.style.overflow = 'visible';
    if (p.flipDirection === 'vertical') backDiv.style.transform = 'rotateX(180deg)';
    else backDiv.style.transform = 'rotateY(180deg)';
    backDiv.style.opacity = editSide === 'front' ? '0' : '1';
    backDiv.style.pointerEvents = editSide === 'front' ? 'none' : 'auto';
    if (backCol) backDiv.appendChild(renderNodeDOM(backCol));
    else { const ph = createPlaceholder('Column'); ph.innerText = 'Empty Flip Card Back'; backDiv.appendChild(ph); }

    flipper.appendChild(frontDiv);
    flipper.appendChild(backDiv);
    container.appendChild(flipper);
    const badge = document.createElement('div'); badge.className = 'node-badge'; badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`; const shouldShow = structureLabelsVisible || (node.id === selectedId); if (!shouldShow) badge.classList.add('hidden-label'); container.appendChild(badge);
    return container;
  }

  function renderFloating(node) {
    const p = node.properties;
    const wrapper = document.createElement('div');
    wrapper.className = 'floating-overlay';
    wrapper.setAttribute('data-node-id', node.id);
    wrapper.setAttribute('data-type', node.type);
    wrapper.style.pointerEvents = 'none';
    wrapper.style.background = 'transparent';
    const isActive = selectedId && (node.id === selectedId || isDescendant(node, selectedId));
    wrapper.style.display = isActive ? '' : 'none';

    const floatX = p.floatingX || '50';
    const floatXUnit = p.floatingXUnit || '%';
    const floatY = p.floatingY || '50';
    const floatYUnit = p.floatingYUnit || '%';
    const floatW = p.floatingWidth || '400';
    const floatWUnit = p.floatingWidthUnit || 'px';
    const floatH = p.floatingHeight || '300';
    const floatHUnit = p.floatingHeightUnit || 'px';

    const content = document.createElement('div');
    content.className = 'floating-content';
    content.style.left = floatX + floatXUnit;
    content.style.top = floatY + floatYUnit;
    content.style.transform = `translate(-50%, -50%)` + (p.rotation ? ` rotate(${p.rotation}deg)` : '');
    content.style.width = floatW + floatWUnit;
    content.style.height = floatH + floatHUnit;
    content.style.zIndex = p.floatingZIndex || 10000;
    content.style.overflow = 'auto';
    content.style.pointerEvents = 'auto';
    content.style.position = 'absolute';
    content.style.display = 'flex';
    content.style.flexDirection = 'column';
    content.style.gap = toPx(p.gap || '16');
    content.style.justifyContent = p.mainAxisAlignment || 'flex-start';
    content.style.alignItems = p.crossAxisAlignment || 'stretch';

    const bgStyle = getBackgroundStyle(node);
    content.style.background = bgStyle;
    content.style.padding = dirToCss(p.padding);
    content.style.borderRadius = radiusToCss(p.borderRadius);

    let shadowCss = 'none';
    if (p.shadowColor && p.shadowBlur !== undefined) {
      shadowCss = `${p.shadowOffsetX || 0}px ${p.shadowOffsetY || 0}px ${p.shadowBlur || 0}px ${p.shadowSpread || 0}px ${p.shadowColor}`;
    }
    content.style.boxShadow = shadowCss !== 'none' ? shadowCss : '0 20px 60px rgba(0,0,0,0.3)';

    if (p.borderWidth > 0 && p.borderStyle && p.borderColor) {
      const borderVal = `${p.borderWidth}px ${p.borderStyle} ${p.borderColor}`;
      if (p.borderSide === 'all') { content.style.border = borderVal; }
      else { const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[p.borderSide]) content.style[sideMap[p.borderSide]] = borderVal; }
    } else { content.style.border = 'none'; }

    content.style.opacity = p.opacity !== undefined ? Number(p.opacity) : 1;

    if (isActive) {
      content.style.outline = '2px solid #3b82f6';
      content.style.outlineOffset = '2px';
    }

    content.setAttribute('data-node-id', node.id);
    content.setAttribute('data-type', node.type);

    content.addEventListener('click', (e) => { e.stopPropagation(); });

    if (node.children && node.children.length) {
      node.children.forEach(ch => content.appendChild(renderNodeDOM(ch)));
    } else {
      content.appendChild(createPlaceholder(node.type));
    }

    const badge = document.createElement('div');
    badge.className = 'node-badge';
    badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
    const shouldShowBadge = structureLabelsVisible || (node.id === selectedId);
    if (!shouldShowBadge) badge.classList.add('hidden-label');
    content.appendChild(badge);

    wrapper.appendChild(content);
    return wrapper;
  }

  function renderNodeDOM(node) {
    let el; const props = node.properties; if (props.padding && typeof props.padding !== 'object') props.padding = normalizeDirProp(props.padding); if (props.margin && typeof props.margin !== 'object') props.margin = normalizeDirProp(props.margin); if (props.borderRadius && typeof props.borderRadius !== 'object') props.borderRadius = normalizeRadiusProp(props.borderRadius);
    let borderCss = 'none'; if (props.borderWidth > 0 && props.borderStyle && props.borderColor) { const borderVal = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`; if (props.borderSide === 'all') borderCss = borderVal; else borderCss = 'none'; }
    let shadowCss = 'none'; if (props.shadowColor && props.shadowBlur !== undefined) shadowCss = `${props.shadowOffsetX}px ${props.shadowOffsetY}px ${props.shadowBlur}px ${props.shadowSpread}px ${props.shadowColor}`;
    const bgStyle = getBackgroundStyle(node); const widthValue = props.width === 'auto' ? 'auto' : (isNaN(Number(props.width)) ? props.width : props.width + (props.widthUnit || 'px')); const heightValue = props.height === 'auto' ? 'auto' : (isNaN(Number(props.height)) ? props.height : props.height + (props.heightUnit || 'px'));
    const baseStyle = { background: bgStyle, padding: dirToCss(props.padding), margin: dirToCss(props.margin), borderRadius: radiusToCss(props.borderRadius), width: widthValue, height: heightValue, minWidth: props.minWidth ? toPx(props.minWidth) : '', minHeight: props.minHeight ? toPx(props.minHeight) : '', maxWidth: props.maxWidth ? toPx(props.maxWidth) : '', maxHeight: props.maxHeight ? toPx(props.maxHeight) : '', boxShadow: shadowCss, overflowY: props.scrollable === true ? 'auto' : 'visible', maxHeight: props.scrollable === true ? '300px' : 'none', position: 'relative', opacity: props.opacity !== undefined ? Number(props.opacity) : 1, transform: props.rotation ? `rotate(${props.rotation}deg)` : 'none' };
    if (props.heightUnit === '%' && LAYOUT_TYPES.includes(node.type)) {
      baseStyle.flex = '1';
      baseStyle.height = 'auto';
    }
    if (node.type === 'Page') {
      el = document.createElement('div');
      el.setAttribute('data-node-id', node.id);
      el.setAttribute('data-type', node.type);
      el.style.cursor = 'pointer';
      const pageBg = getBackgroundStyle(node);
      el.style.background = pageBg;
      const maxW = props.maxWidth && props.maxWidth !== '' ? toPx(props.maxWidth) : 'none';
      el.style.maxWidth = maxW;
      el.style.width = (props.width && props.width !== 'auto') ? toPx(props.width) : '100%';
      el.style.margin = '0 auto';
      el.style.padding = toPx(props.pagePadding);
      el.style.fontFamily = props.defaultFont;
      el.style.color = props.defaultTextColor;
      el.style.minHeight = '100%';
      el.style.flex = '1';
      if (node.children) node.children.forEach(ch => {
        el.appendChild(renderNodeDOM(ch));
      });
      const badge = document.createElement('div');
      badge.className = 'node-badge';
      badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
      const shouldShow = structureLabelsVisible || (node.id === selectedId);
      if (!shouldShow) badge.classList.add('hidden-label');
      el.appendChild(badge);
      return el;
    }
    if (props.borderWidth > 0 && props.borderStyle && props.borderColor && props.borderSide !== 'all') { const borderVal = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`; const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[props.borderSide]) baseStyle[sideMap[props.borderSide]] = borderVal; } else if (props.borderWidth > 0 && props.borderSide === 'all') baseStyle.border = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`;
    if (node.type === 'HiddenRoot') { el = document.createElement('div'); el.classList.add('hidden-root'); el.style.display = 'flex'; el.style.flexDirection = 'column'; el.style.gap = toPx(props.gap); el.style.justifyContent = props.mainAxisAlignment; el.style.alignItems = props.crossAxisAlignment; el.style.background = 'transparent'; el.style.backgroundColor = 'transparent'; el.style.border = 'none'; el.style.boxShadow = 'none'; el.style.padding = '0'; el.style.margin = '0'; el.style.flex = '1'; el.style.minHeight = '100%'; el.setAttribute('data-node-id', node.id); if (node.children) node.children.forEach(ch => { el.appendChild(renderNodeDOM(ch)); }); return el; }
    if (node.type === 'Floating') { el = renderFloating(node); return el; }
    if (node.type === 'Column') { el = document.createElement('div'); el.style.display = 'flex'; el.style.flexDirection = 'column'; el.style.gap = toPx(props.gap); el.style.justifyContent = props.mainAxisAlignment; el.style.alignItems = props.crossAxisAlignment; Object.assign(el.style, baseStyle); if (node.children && node.children.length) node.children.forEach(ch => el.appendChild(renderNodeDOM(ch))); else { el.appendChild(createPlaceholder(node.type)); } }
    else if (node.type === 'Row') { el = document.createElement('div'); el.style.display = 'flex'; el.style.flexDirection = props.wrapReverse ? 'row-reverse' : 'row'; el.style.flexWrap = props.wrapEnabled ? 'wrap' : 'nowrap'; el.style.overflowX = props.wrapEnabled ? 'visible' : 'auto'; el.style.gap = toPx(props.gap); el.style.justifyContent = props.mainAxisAlignment; el.style.alignItems = props.crossAxisAlignment; Object.assign(el.style, baseStyle); if (node.children && node.children.length) node.children.forEach(ch => el.appendChild(renderNodeDOM(ch))); else { el.style.width = '100%'; el.appendChild(createPlaceholder(node.type)); } }
    else if (node.type === 'GridView') { el = document.createElement('div'); el.style.display = 'grid'; el.style.gridTemplateColumns = 'repeat(auto-fill, minmax(min(200px, 100%), 1fr))'; el.style.gap = toPx(props.gap); el.style.justifyItems = props.mainAxisAlignment === 'center' ? 'center' : (props.mainAxisAlignment === 'flex-end' ? 'end' : 'start'); el.style.alignItems = props.crossAxisAlignment === 'center' ? 'center' : (props.crossAxisAlignment === 'flex-end' ? 'end' : 'start'); el.style.width = '100%'; Object.assign(el.style, baseStyle); if (node.children && node.children.length) node.children.forEach(ch => el.appendChild(renderNodeDOM(ch))); else el.appendChild(createPlaceholder(node.type)); }
    else if (node.type === 'Stack') { el = document.createElement('div'); el.style.position = 'relative'; Object.assign(el.style, baseStyle); if (node.children && node.children.length) { node.children.forEach(ch => { const childEl = renderNodeDOM(ch); childEl.style.position = 'absolute'; childEl.style.left = (ch.properties.leftPercent !== undefined ? ch.properties.leftPercent : 0) + '%'; childEl.style.top = (ch.properties.topPercent !== undefined ? ch.properties.topPercent : 0) + '%'; if (ch.properties.right !== null) childEl.style.right = toPx(ch.properties.right); if (ch.properties.bottom !== null) childEl.style.bottom = toPx(ch.properties.bottom); childEl.classList.add('stack-child'); el.appendChild(childEl); }); enableStackDragging(el); } else el.appendChild(createPlaceholder(node.type)); }
    else if (node.type === 'Card') { el = document.createElement('div'); el.style.boxShadow = shadowCss; el.style.borderRadius = radiusToCss(props.borderRadius); Object.assign(el.style, baseStyle); if (node.children && node.children.length) node.children.forEach(ch => el.appendChild(renderNodeDOM(ch))); else el.appendChild(createPlaceholder(node.type)); }
    else if (node.type === 'Text') { el = document.createElement('div'); el.innerText = props.text; applyTextStyle(el, props); Object.assign(el.style, baseStyle); }
    else if (node.type === 'Button') { el = document.createElement('button'); el.innerText = props.text; const btnBg = getBackgroundStyle(node); el.style.background = btnBg; applyTextStyle(el, props); if (props.borderWidth > 0 && props.borderStyle && props.borderColor) { if (props.borderSide === 'all') el.style.border = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`; else { const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[props.borderSide]) el.style[sideMap[props.borderSide]] = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`; } } el.style.padding = dirToCss(props.padding, 'px'); el.style.borderRadius = radiusToCss(props.borderRadius); Object.assign(el.style, baseStyle); }
    else if (node.type === 'Image') {
      const wrapper = document.createElement('div');
      wrapper.style.position = 'relative';
      wrapper.style.display = 'inline-block';
      wrapper.setAttribute('data-node-id', node.id);
      wrapper.setAttribute('data-type', node.type);
      wrapper.style.cursor = 'pointer';
      const img = document.createElement('img');
      img.src = props.src;
      img.style.width = baseStyle.width !== 'auto' ? baseStyle.width : '100%';
      img.style.height = baseStyle.height !== 'auto' ? baseStyle.height : 'auto';
      img.style.minWidth = baseStyle.minWidth || '';
      img.style.minHeight = baseStyle.minHeight || '';
      img.style.maxWidth = baseStyle.maxWidth || '';
      img.style.maxHeight = baseStyle.maxHeight || '';
      img.style.borderRadius = baseStyle.borderRadius;
      img.style.boxShadow = baseStyle.boxShadow;
      img.style.margin = baseStyle.margin;
      img.style.padding = baseStyle.padding;
      img.style.opacity = baseStyle.opacity;
      img.style.transform = baseStyle.transform;
      img.style.background = baseStyle.background;
      img.style.objectFit = props.objectFit || 'cover';
      img.style.display = 'block';
      if (props.borderWidth > 0 && props.borderStyle && props.borderColor) {
        if (props.borderSide === 'all') {
          img.style.border = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`;
        } else {
          img.style.border = 'none';
          const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' };
          if (sideMap[props.borderSide]) img.style[sideMap[props.borderSide]] = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`;
        }
      } else {
        img.style.border = 'none';
      }
      wrapper.appendChild(img);
      const badge = document.createElement('div'); badge.className = 'node-badge'; badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
      if (!(structureLabelsVisible || node.id === selectedId)) badge.classList.add('hidden-label'); wrapper.appendChild(badge);
      el = wrapper;
    }
    else if (node.type === 'Video') { const wrapper = document.createElement('div'); wrapper.style.position = 'relative'; wrapper.style.display = 'inline-block'; wrapper.setAttribute('data-node-id', node.id); wrapper.setAttribute('data-type', node.type); wrapper.style.cursor = 'pointer'; const video = document.createElement('video'); video.src = props.src; video.controls = true; video.style.width = baseStyle.width !== 'auto' ? baseStyle.width : '100%'; video.style.height = baseStyle.height !== 'auto' ? baseStyle.height : 'auto'; video.style.minWidth = baseStyle.minWidth || ''; video.style.minHeight = baseStyle.minHeight || ''; video.style.maxWidth = baseStyle.maxWidth || ''; video.style.maxHeight = baseStyle.maxHeight || ''; video.style.borderRadius = baseStyle.borderRadius; video.style.border = baseStyle.border; video.style.boxShadow = baseStyle.boxShadow; video.style.margin = baseStyle.margin; video.style.padding = baseStyle.padding; video.style.opacity = baseStyle.opacity; video.style.transform = baseStyle.transform; video.style.background = baseStyle.background; video.style.display = 'block'; wrapper.appendChild(video); const badge = document.createElement('div'); badge.className = 'node-badge'; badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`; if (!(structureLabelsVisible || node.id === selectedId)) badge.classList.add('hidden-label'); wrapper.appendChild(badge); el = wrapper; }
    else if (node.type === 'TextField') { const wrapper = document.createElement('div'); Object.assign(wrapper.style, baseStyle); wrapper.style.position = 'relative'; const input = document.createElement('input'); input.placeholder = props.hint || 'Type'; input.style.padding = dirToCss(props.padding); input.style.border = '1px solid #cbd5e1'; input.style.borderRadius = radiusToCss(props.borderRadius); input.style.width = '100%'; input.style.boxSizing = 'border-box'; applyTextStyle(input, props); wrapper.appendChild(input); el = wrapper; }
    else if (node.type === 'Divider') { const wrapper = document.createElement('div'); Object.assign(wrapper.style, baseStyle); wrapper.style.position = 'relative'; const hr = document.createElement('hr'); hr.style.height = toPx(props.height) || '2px'; hr.style.backgroundColor = props.backgroundColor || '#D1D5DB'; hr.style.border = 'none'; hr.style.margin = '0'; wrapper.appendChild(hr); el = wrapper; }
    else if (node.type === 'Icon') {
      const wrapper = document.createElement('div');
      wrapper.style.position = 'relative';
      wrapper.style.display = 'inline-flex';
      wrapper.style.alignItems = 'center';
      wrapper.style.justifyContent = 'center';
      wrapper.style.margin = dirToCss(props.margin);
      wrapper.style.padding = dirToCss(props.padding);
      wrapper.setAttribute('data-node-id', node.id);
      wrapper.setAttribute('data-type', node.type);
      wrapper.style.cursor = 'pointer';
      const iconEl = document.createElement('i');
      iconEl.className = 'material-icons';
      iconEl.innerText = props.iconName || 'star';
      const iconBg = getBackgroundStyle(node);
      iconEl.style.background = iconBg;
      iconEl.style.fontSize = toPx(props.fontSize) || '24px';
      iconEl.style.color = props.color || '#3b82f6';
      iconEl.style.width = baseStyle.width !== 'auto' ? baseStyle.width : 'auto';
      iconEl.style.height = baseStyle.height !== 'auto' ? baseStyle.height : 'auto';
      iconEl.style.minWidth = baseStyle.minWidth || '';
      iconEl.style.minHeight = baseStyle.minHeight || '';
      iconEl.style.maxWidth = baseStyle.maxWidth || '';
      iconEl.style.maxHeight = baseStyle.maxHeight || '';
      iconEl.style.borderRadius = baseStyle.borderRadius;
      if (props.borderWidth > 0 && props.borderStyle && props.borderColor) {
        if (props.borderSide === 'all') iconEl.style.border = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`;
        else { const sideMap = { top:'borderTop', right:'borderRight', bottom:'borderBottom', left:'borderLeft' }; if (sideMap[props.borderSide]) iconEl.style[sideMap[props.borderSide]] = `${props.borderWidth}px ${props.borderStyle} ${props.borderColor}`; }
      } else { iconEl.style.border = 'none'; }
      iconEl.style.boxShadow = shadowCss;
      iconEl.style.opacity = props.opacity !== undefined ? Number(props.opacity) : 1;
      iconEl.style.transform = props.rotation ? `rotate(${props.rotation}deg)` : 'none';
      iconEl.style.display = 'flex';
      iconEl.style.alignItems = 'center';
      iconEl.style.justifyContent = 'center';
      wrapper.appendChild(iconEl);
      const badge = document.createElement('div');
      badge.className = 'node-badge';
      badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
      const shouldShow = structureLabelsVisible || (node.id === selectedId);
      if (!shouldShow) badge.classList.add('hidden-label');
      wrapper.appendChild(badge);
      el = wrapper;
    }
    else if (node.type === 'Countdown') { el = renderCountdown(node); el.setAttribute('data-node-id', node.id); el.setAttribute('data-type', node.type); el.style.cursor = 'pointer'; }
    else if (node.type === 'Carousel') { el = renderCarousel(node); }
    else if (node.type === 'Table') { el = renderTable(node); }
    else if (node.type === 'ProgressBar') { el = renderProgressBar(node); }
    else if (node.type === 'Chart') { el = renderChart(node); }
    else if (node.type === 'FlippableCard') { el = renderFlippableCard(node); }
    else { el = document.createElement('div'); el.innerText = node.type; Object.assign(el.style, baseStyle); }
    if (node.type !== 'Page' && node.type !== 'HiddenRoot' && node.type !== 'Icon' && node.type !== 'Image' && node.type !== 'Video' && node.type !== 'FlippableCard' && node.type !== 'Floating') {
      if (!el.getAttribute('data-node-id')) { el.setAttribute('data-node-id', node.id); el.setAttribute('data-type', node.type); el.style.cursor = 'pointer'; }
      let hasBadge = false;
      for (let child of el.children) {
        if (child.classList && child.classList.contains('node-badge')) { hasBadge = true; break; }
      }
      if (!hasBadge) {
        const badge = document.createElement('div');
        badge.className = 'node-badge';
        badge.innerHTML = `<i class="${getIconForType(node.type)}"></i><span>${node.displayName || node.type}</span>`;
        if (!(structureLabelsVisible || node.id === selectedId)) badge.classList.add('hidden-label');
        el.appendChild(badge);
      }
    }
    return el;
  }

  function applyMarginVisualization() { document.querySelectorAll('.margin-overlay').forEach(o => o.remove()); if (!selectedId || selectedId === tree.id) return; const node = findNode(tree, selectedId); if (!node || node.type === 'HiddenRoot') return; const el = document.querySelector(`[data-node-id="${selectedId}"]`); if (!el) return; const props = node.properties; if (!props.margin) return; const mar = typeof props.margin === 'object' ? props.margin : { top:0,right:0,bottom:0,left:0 }; const mTop = parseFloat(mar.top)||0, mRight = parseFloat(mar.right)||0, mBottom = parseFloat(mar.bottom)||0, mLeft = parseFloat(mar.left)||0; if (mTop===0 && mRight===0 && mBottom===0 && mLeft===0) return; const overlay = document.createElement('div'); overlay.className = 'margin-overlay'; overlay.style.position = 'absolute'; overlay.style.pointerEvents = 'none'; overlay.style.zIndex = '-1'; overlay.style.top = `-${mTop}px`; overlay.style.left = `-${mLeft}px`; overlay.style.width = `calc(100% + ${mLeft+mRight}px)`; overlay.style.height = `calc(100% + ${mTop+mBottom}px)`; overlay.style.boxSizing = 'border-box'; el.style.position = 'relative'; if (el.firstChild) el.insertBefore(overlay, el.firstChild); else el.appendChild(overlay); }

  function enableStackDragging(stackContainer) { const children = stackContainer.querySelectorAll('.stack-child'); children.forEach(child => { child.setAttribute('draggable','false'); child.removeEventListener('mousedown', startDrag); child.removeEventListener('touchstart', startDrag); child.addEventListener('mousedown', startDrag); child.addEventListener('touchstart', startDrag, { passive: false }); }); function startDrag(e) { e.preventDefault(); e.stopPropagation(); const targetEl = e.target.closest('.stack-child'); if (!targetEl) return; const nodeId = targetEl.getAttribute('data-node-id'); if (!nodeId) return; const startX = e.clientX || (e.touches?e.touches[0].clientX:0), startY = e.clientY || (e.touches?e.touches[0].clientY:0); const startLeft = parseFloat(targetEl.style.left)||0, startTop = parseFloat(targetEl.style.top)||0; const stackRect = stackContainer.getBoundingClientRect(), childRect = targetEl.getBoundingClientRect(); const maxLeft = stackRect.width - childRect.width, maxTop = stackRect.height - childRect.height; function onMove(moveEvent) { moveEvent.preventDefault(); const currentX = moveEvent.clientX || (moveEvent.touches?moveEvent.touches[0].clientX:0), currentY = moveEvent.clientY || (moveEvent.touches?moveEvent.touches[0].clientY:0); let dx = currentX - startX, dy = currentY - startY; let newLeft = startLeft + dx, newTop = startTop + dy; newLeft = Math.min(Math.max(0, newLeft), maxLeft); newTop = Math.min(Math.max(0, newTop), maxTop); targetEl.style.left = newLeft+'px'; targetEl.style.top = newTop+'px'; const node = findNode(tree, nodeId); if (node) { const pctLeft = stackRect.width > 0 ? (newLeft / stackRect.width) * 100 : 0; const pctTop = stackRect.height > 0 ? (newTop / stackRect.height) * 100 : 0; node.properties.leftPercent = pctLeft; node.properties.topPercent = pctTop; node.properties.left = newLeft; node.properties.top = newTop; saveToHistory(); } } function onUp() { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); window.removeEventListener('touchmove', onMove); window.removeEventListener('touchend', onUp); fullRender(); } window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp); window.addEventListener('touchmove', onMove, { passive: false }); window.addEventListener('touchend', onUp); } }

  function createPlaceholder(type) { const div = document.createElement('div'); div.className = 'placeholder-layout'; const map = { 'Column':'Empty Column','Row':'Empty Row','GridView':'Empty Grid','Container':'Empty Container','Stack':'Empty Stack','Carousel':'Empty Carousel','Card':'Empty Card','FlippableCard':'Empty FlippableCard','Floating':'Empty Floating' }; div.innerText = map[type] || 'Drop content here'; return div; }
  let currentSortableInstances = [];

  function isFloatingVisible(nodeId) {
    const node = findNode(tree, nodeId);
    if (!node || node.type !== 'Floating') return false;
    return selectedId && (node.id === selectedId || isDescendant(node, selectedId));
  }

  // ========== VISIBILITY EVALUATION ENGINE (for Preview/Export) ==========
  function resolveDynamicValue(path) {
    if (!path) return '';
    if (path.startsWith('global.')) {
      const parts = path.split('.');
      const prop = parts[1];
      if (prop === 'screenWidth') return window.innerWidth;
      if (prop === 'screenHeight') return window.innerHeight;
      if (prop === 'orientation') return window.innerWidth > window.innerHeight ? 'landscape' : 'portrait';
      if (prop === 'platform') return /Mobi|Android/i.test(navigator.userAgent) ? 'mobile' : 'web';
      if (prop === 'time') return new Date().toLocaleTimeString();
      if (prop === 'date') return new Date().toLocaleDateString();
      if (prop === 'screenSize') return `${window.innerWidth}x${window.innerHeight}`;
      if (prop === 'language') return navigator.language;
      if (prop === 'locale') return navigator.language;
      if (prop === 'theme') return 'light';
      if (prop === 'isDarkMode') return 'false';
      if (prop === 'isLightMode') return 'true';
      if (prop === 'isWeb') return 'true';
      if (prop === 'isAndroid') return /Android/i.test(navigator.userAgent).toString();
      if (prop === 'isiOS') return /iPhone|iPad|iPod/i.test(navigator.userAgent).toString();
      if (prop === 'pageUrl') return window.location.href;
      if (prop === 'path') return window.location.pathname;
      if (prop === 'location') return '';
      if (prop === 'safeArea') return '';
      if (prop === 'keyboardVisible') return 'false';
      if (prop === 'textScale') return '1';
      if (prop === 'timezone') return Intl.DateTimeFormat().resolvedOptions().timeZone;
      return '';
    }
    if (path.startsWith('widget.')) {
      const widgetName = path.split('.')[1];
      const widgetNode = findNode(tree, null, (n) => n.displayName === widgetName);
      if (widgetNode && widgetNode.type === 'TextField') return widgetNode.properties.text || '';
      if (widgetNode && widgetNode.type === 'Button') return widgetNode.properties.text || '';
      return '';
    }
    return '';
  }

  function evaluateCondition(cond) {
    const firstVal = cond.firstDynamic ? resolveDynamicValue(cond.firstDynamicPath) : cond.firstValue;
    const secondVal = cond.secondDynamic ? resolveDynamicValue(cond.secondDynamicPath) : cond.secondValue;
    const op = cond.operator;
    if (op === 'Equals') return String(firstVal) === String(secondVal);
    if (op === 'Not Equals') return String(firstVal) !== String(secondVal);
    const a = parseFloat(firstVal), b = parseFloat(secondVal);
    if (isNaN(a) || isNaN(b)) {
      if (op === 'Contains') return String(firstVal).includes(String(secondVal));
      if (op === 'Does Not Contain') return !String(firstVal).includes(String(secondVal));
      if (op === 'Starts With') return String(firstVal).startsWith(String(secondVal));
      if (op === 'Ends With') return String(firstVal).endsWith(String(secondVal));
      if (op === 'Is Empty') return String(firstVal).trim() === '';
      if (op === 'Is Not Empty') return String(firstVal).trim() !== '';
      return false;
    }
    if (op === 'Greater Than') return a > b;
    if (op === 'Less Than') return a < b;
    if (op === 'Greater Than or Equal') return a >= b;
    if (op === 'Less Than or Equal') return a <= b;
    return false;
  }

  // Used in preview/export only; editor canvas ignores visibility
  function shouldShowNodeInPreview(node) {
    const vis = node.properties.visibility;
    if (!vis || !vis.enabled) return true;
    const width = window.innerWidth;
    if (width >= 1024 && !vis.responsiveVisibility.desktop) return false;
    if (width >= 768 && width < 1024 && !vis.responsiveVisibility.tablet) return false;
    if (width < 768 && !vis.responsiveVisibility.mobile) return false;
    const conditions = vis.conditions || [];
    if (conditions.length === 0) return true;
    const combinators = vis.conditionCombinators || [];
    let result = evaluateCondition(conditions[0]);
    for (let i = 1; i < conditions.length; i++) {
      const combinator = combinators[i-1] || 'AND';
      const nextResult = evaluateCondition(conditions[i]);
      result = combinator === 'AND' ? (result && nextResult) : (result || nextResult);
    }
    return result;
  }

  // ========== FULL RENDER (canvas always shows all widgets) ==========
  function fullRender() {
    const container = document.getElementById('canvasRender');
    if (!container) return;
    container.innerHTML = '';
    const rendered = renderNodeDOM(tree);
    container.appendChild(rendered);

    // Only apply canvasHidden (eye icon in tree); NEVER hide based on visibility conditions
    document.querySelectorAll('[data-node-id]').forEach(el => {
      const nid = el.getAttribute('data-node-id');
      if (!nid) return;
      const node = findNode(tree, nid);
      if (node && node.type !== 'Page' && node.type !== 'HiddenRoot' && node.properties.canvasHidden) {
        el.style.display = 'none';
      }
    });

    currentSortableInstances.forEach(s => s.destroy());
    currentSortableInstances = [];
    function initSortable(containerEl) {
      if (!containerEl) return;
      const sortable = new Sortable(containerEl, {
        group: { name: 'shared', pull: true, revertClone: false },
        animation: 200, sort: true, ghostClass: 'sortable-ghost', dragClass: 'sortable-drag',
        draggable: '[data-node-id]:not(.floating-content)',
        onStart: () => {
          const hiddenRoot = document.querySelector('.hidden-root');
          if (hiddenRoot) hiddenRoot.classList.add('drag-active');
        },
        onEnd: () => {
          const hiddenRoot = document.querySelector('.hidden-root');
          if (hiddenRoot) hiddenRoot.classList.remove('drag-active');
        },
        onEnd: (evt) => {
          const draggedNodeId = evt.item.getAttribute('data-node-id');
          const targetParentEl = evt.to;
          const targetParentId = targetParentEl.getAttribute('data-node-id');
          if (!draggedNodeId || !targetParentId) return;
          const sourceParent = getParent(tree, draggedNodeId);
          const targetParentNode = findNode(tree, targetParentId);
          if (!sourceParent || !targetParentNode) return;
          const childNodes = Array.from(targetParentEl.children).filter(child => child.hasAttribute('data-node-id'));
          const newOrder = childNodes.map(child => child.getAttribute('data-node-id'));
          if (sourceParent.id === targetParentNode.id) {
            const orderedNodes = newOrder.map(id => targetParentNode.children.find(c => c.id === id)).filter(c => c);
            targetParentNode.children = orderedNodes;
          } else {
            let movedNode = findNode(tree, draggedNodeId);
            if (!movedNode) return;
            sourceParent.children = sourceParent.children.filter(c => c.id !== draggedNodeId);
            let actualTarget = targetParentNode;
            if (targetParentNode.type === 'FlippableCard') {
              const editSide = targetParentNode.properties.editSide || 'front';
              let sideColumn = targetParentNode.children.find(c => c.displayName === (editSide === 'front' ? 'Front' : 'Back'));
              if (!sideColumn || sideColumn.type !== 'Column') {
                sideColumn = createNode('Column');
                sideColumn.displayName = editSide === 'front' ? 'Front' : 'Back';
                sideColumn.properties.padding = { top: 16, right: 16, bottom: 16, left: 16 };
                if (!targetParentNode.children) targetParentNode.children = [];
                targetParentNode.children.push(sideColumn);
              }
              actualTarget = sideColumn;
            }
            if (actualTarget.type === 'HiddenRoot' && !isLayoutType(movedNode.type)) {
              const column = createNode('Column');
              column.displayName = 'Auto Column';
              column.children = [movedNode];
              movedNode = column;
            } else if (!isLayoutContainer(actualTarget.type) && actualTarget.type !== 'HiddenRoot') {
              const column = createNode('Column');
              column.displayName = 'Auto Column';
              column.children = [movedNode];
              movedNode = column;
            }
            if (!actualTarget.children) actualTarget.children = [];
            const dropIndex = newOrder.findIndex(id => id === draggedNodeId);
            if (dropIndex !== -1) {
              actualTarget.children.splice(dropIndex, 0, movedNode);
            } else {
              actualTarget.children.push(movedNode);
            }
            selectedId = movedNode.id;
          }
          saveToHistory();
          fullRender();
          updatePropsPanel();
          const hiddenRoot = document.querySelector('.hidden-root');
          if (hiddenRoot) hiddenRoot.classList.remove('drag-active');
        }
      });
      currentSortableInstances.push(sortable);
    }
    const hiddenRootEl = container.querySelector('.hidden-root');
    if (hiddenRootEl) initSortable(hiddenRootEl);
    const allLayouts = document.querySelectorAll('[data-type="Column"], [data-type="Row"], [data-type="GridView"], [data-type="Card"], [data-type="Stack"], [data-type="Carousel"], [data-type="Floating"]');
    allLayouts.forEach(containerEl => {
      if (containerEl.getAttribute('data-type') === 'Floating') {
        const floatingContent = containerEl.querySelector('.floating-content');
        if (floatingContent) initSortable(floatingContent);
        return;
      }
      initSortable(containerEl);
    });

    for (let [id, interval] of countdownIntervals.entries()) {
      if (!findNode(tree, id)) { clearInterval(interval); countdownIntervals.delete(id); }
    }
    for (let [id, interval] of carouselIntervals.entries()) {
      if (!findNode(tree, id)) { clearInterval(interval); carouselIntervals.delete(id); }
    }
    function startIntervals(node) {
      if (node.type === 'Countdown') { startCountdownInterval(node.id); }
      if (node.children) node.children.forEach(startIntervals);
    }
    startIntervals(tree);

    attachSelectionListeners();
    if (selectedId && selectedId !== tree.id) {
      const selectedEl = document.querySelector(`[data-node-id="${selectedId}"]`);
      if (selectedEl && !selectedEl.classList.contains('hidden-root')) selectedEl.classList.add('selected-node');
    }
    if (selectedId) {
      const selectedEl = document.querySelector(`[data-node-id="${selectedId}"]`);
      if (selectedEl) {
        const badge = selectedEl.querySelector(':scope > .node-badge');
        if (badge) badge.classList.remove('hidden-label');
      }
    }
    applyMarginVisualization();
  }
