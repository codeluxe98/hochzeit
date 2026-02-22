(() => {
    const menuToggle = document.querySelector('.menu-toggle');
    const mainNav = document.getElementById('mainNav');

    if (menuToggle && mainNav) {
        menuToggle.addEventListener('click', () => {
            const expanded = menuToggle.getAttribute('aria-expanded') === 'true';
            menuToggle.setAttribute('aria-expanded', String(!expanded));
            mainNav.classList.toggle('is-open');
        });

        mainNav.querySelectorAll('a[href^="#"]').forEach((link) => {
            link.addEventListener('click', () => {
                if (window.innerWidth <= 860) {
                    mainNav.classList.remove('is-open');
                    menuToggle.setAttribute('aria-expanded', 'false');
                }
            });
        });
    }

    const revealElements = document.querySelectorAll('.reveal');
    if ('IntersectionObserver' in window && revealElements.length > 0) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.12 });

        revealElements.forEach((element) => observer.observe(element));
    } else {
        revealElements.forEach((element) => element.classList.add('visible'));
    }

    const lazyImages = document.querySelectorAll('img.lazy[data-src]');
    if ('IntersectionObserver' in window && lazyImages.length > 0) {
        const imageObserver = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    return;
                }

                const img = entry.target;
                const src = img.getAttribute('data-src');
                if (src) {
                    img.setAttribute('src', src);
                    img.removeAttribute('data-src');
                }
                imageObserver.unobserve(img);
            });
        }, { rootMargin: '100px 0px' });

        lazyImages.forEach((img) => imageObserver.observe(img));
    }

    const tabButtons = document.querySelectorAll('.tab-btn[data-tab-target]');
    if (tabButtons.length > 0) {
        tabButtons.forEach((button) => {
            button.addEventListener('click', () => {
                const targetId = button.getAttribute('data-tab-target');
                if (!targetId) {
                    return;
                }

                document.querySelectorAll('.tab-btn').forEach((btn) => btn.classList.remove('is-active'));
                document.querySelectorAll('.tab-content').forEach((tab) => tab.classList.remove('is-active'));

                button.classList.add('is-active');
                const targetTab = document.getElementById(targetId);
                if (targetTab) {
                    targetTab.classList.add('is-active');
                }
            });
        });
    }

    const dropzones = document.querySelectorAll('[data-dropzone][data-input-id]');
    if (dropzones.length > 0) {
        dropzones.forEach((dropzone) => {
            const inputId = dropzone.getAttribute('data-input-id');
            if (!inputId) {
                return;
            }

            const fileInput = document.getElementById(inputId);
            if (!(fileInput instanceof HTMLInputElement)) {
                return;
            }

            const filesLabel = dropzone.querySelector('[data-dropzone-files]');

            const renderSelectedFiles = () => {
                if (!filesLabel) {
                    return;
                }

                const names = Array.from(fileInput.files || []).map((file) => file.name);
                if (names.length === 0) {
                    filesLabel.textContent = 'Noch keine Dateien ausgewählt.';
                    return;
                }

                filesLabel.textContent = names.join(' | ');
            };

            const setInputFiles = (files) => {
                if (typeof DataTransfer !== 'undefined') {
                    const transfer = new DataTransfer();
                    files.forEach((file) => transfer.items.add(file));
                    fileInput.files = transfer.files;
                } else {
                    try {
                        fileInput.files = files;
                    } catch (error) {
                        return;
                    }
                }
                renderSelectedFiles();
            };

            const addFilesToInput = (files) => {
                const currentFiles = Array.from(fileInput.files || []);
                const addedFiles = Array.from(files || []);
                if (addedFiles.length === 0) {
                    return;
                }

                const merged = [...currentFiles];
                addedFiles.forEach((incoming) => {
                    const exists = merged.some((existing) =>
                        existing.name === incoming.name
                        && existing.size === incoming.size
                        && existing.lastModified === incoming.lastModified
                    );
                    if (!exists) {
                        merged.push(incoming);
                    }
                });

                setInputFiles(merged);
            };

            dropzone.addEventListener('click', () => fileInput.click());
            fileInput.addEventListener('change', renderSelectedFiles);

            ['dragenter', 'dragover'].forEach((eventName) => {
                dropzone.addEventListener(eventName, (event) => {
                    event.preventDefault();
                    dropzone.classList.add('is-dragover');
                });
            });

            ['dragleave', 'dragend', 'drop'].forEach((eventName) => {
                dropzone.addEventListener(eventName, (event) => {
                    event.preventDefault();
                    dropzone.classList.remove('is-dragover');
                });
            });

            dropzone.addEventListener('drop', (event) => {
                const droppedFiles = event.dataTransfer?.files;
                if (!droppedFiles || droppedFiles.length === 0) {
                    return;
                }
                addFilesToInput(droppedFiles);
            });

            renderSelectedFiles();
        });
    }

    const uploadForms = document.querySelectorAll('form[data-upload-form]');
    if (uploadForms.length > 0) {
        uploadForms.forEach((form) => {
            const fileInput = form.querySelector('input[type="file"][name="photos[]"]');
            const csrfInput = form.querySelector('input[name="csrf_token"]');
            const progressContainer = form.querySelector('[data-upload-progress]');
            const submitButton = form.querySelector('[data-upload-submit]');

            if (!(fileInput instanceof HTMLInputElement) || !(csrfInput instanceof HTMLInputElement)) {
                return;
            }

            const makeProgressItem = (fileName) => {
                if (!progressContainer) {
                    return null;
                }

                const item = document.createElement('div');
                item.className = 'upload-progress-item';

                const label = document.createElement('div');
                label.className = 'upload-progress-label';
                label.textContent = fileName;

                const bar = document.createElement('div');
                bar.className = 'upload-progress-bar';
                const fill = document.createElement('span');
                fill.style.width = '0%';
                bar.appendChild(fill);

                const status = document.createElement('div');
                status.className = 'upload-progress-status';
                status.textContent = 'Wartet ...';

                item.appendChild(label);
                item.appendChild(bar);
                item.appendChild(status);
                progressContainer.appendChild(item);

                return { item, fill, status };
            };

            const uploadSingleFile = (file, ui) => new Promise((resolve) => {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', form.getAttribute('action') || window.location.pathname, true);
                xhr.responseType = 'json';

                xhr.upload.addEventListener('progress', (event) => {
                    if (!ui || !event.lengthComputable) {
                        return;
                    }
                    const percent = Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100)));
                    ui.fill.style.width = `${percent}%`;
                    ui.status.textContent = `Upload ${percent}%`;
                });

                xhr.addEventListener('load', () => {
                    const response = xhr.response && typeof xhr.response === 'object'
                        ? xhr.response
                        : { success: false, message: 'Ungültige Serverantwort.' };

                    const success = xhr.status >= 200 && xhr.status < 300 && response.success === true;
                    if (ui) {
                        ui.fill.style.width = success ? '100%' : ui.fill.style.width;
                        ui.item.classList.toggle('is-success', success);
                        ui.item.classList.toggle('is-error', !success);
                        ui.status.textContent = String(response.message || (success ? 'Fertig' : 'Fehler'));
                    }
                    resolve(success);
                });

                xhr.addEventListener('error', () => {
                    if (ui) {
                        ui.item.classList.add('is-error');
                        ui.status.textContent = 'Netzwerkfehler beim Upload.';
                    }
                    resolve(false);
                });

                const payload = new FormData();
                payload.append('action', 'upload_single_ajax');
                payload.append('csrf_token', csrfInput.value);
                payload.append('photo', file, file.name);
                xhr.send(payload);
            });

            form.addEventListener('submit', async (event) => {
                const files = Array.from(fileInput.files || []);
                if (files.length === 0 || !progressContainer) {
                    return;
                }

                event.preventDefault();
                progressContainer.innerHTML = '';
                if (submitButton instanceof HTMLButtonElement) {
                    submitButton.disabled = true;
                    submitButton.textContent = 'Upload läuft ...';
                }

                let allSucceeded = true;
                for (const file of files) {
                    const ui = makeProgressItem(file.name);
                    const ok = await uploadSingleFile(file, ui);
                    if (!ok) {
                        allSucceeded = false;
                    }
                }

                if (submitButton instanceof HTMLButtonElement) {
                    submitButton.disabled = false;
                    submitButton.textContent = allSucceeded ? 'Fertig - Seite wird neu geladen ...' : 'Upload abgeschlossen';
                }

                setTimeout(() => {
                    window.location.reload();
                }, allSucceeded ? 700 : 1300);
            });
        });
    }
})();
