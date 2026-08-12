// Every request below is same-origin — the API is nested under this exact
// prefix (see api/config/server.json's "apiRoot") in the very same frogs
// process that's serving this page. No CORS headers, no separate port.
const API_ROOT = "/api";

const booksTable = document.querySelector("#books-table tbody");
const membersTable = document.querySelector("#members-table tbody");
const rentalsTable = document.querySelector("#rentals-table tbody");
const deletedBooksTable = document.querySelector("#deleted-books-table tbody");
const deletedMembersTable = document.querySelector("#deleted-members-table tbody");
const checkoutForm = document.getElementById("checkout-form");
const checkoutBookSelect = document.getElementById("checkout-book");
const checkoutMemberSelect = document.getElementById("checkout-member");
const checkoutStatus = document.getElementById("checkout-status");
const rentalPeriodHint = document.getElementById("rental-period-hint");

const bookDialog = document.getElementById("book-dialog");
const bookDialogTitle = document.getElementById("book-dialog-title");
const bookLookupSection = document.getElementById("book-lookup-section");
const bookLookupQuery = document.getElementById("book-lookup-query");
const bookLookupButton = document.getElementById("book-lookup-button");
const bookLookupStatus = document.getElementById("book-lookup-status");
const bookLookupResults = document.getElementById("book-lookup-results");
const bookForm = document.getElementById("book-form");
const bookTitleInput = document.getElementById("book-title");
const bookAuthorInput = document.getElementById("book-author");
const bookIsbnInput = document.getElementById("book-isbn");
const bookFormStatus = document.getElementById("book-form-status");
const bookSubmitButton = document.getElementById("book-submit-button");

const memberDialog = document.getElementById("member-dialog");
const memberDialogTitle = document.getElementById("member-dialog-title");
const memberForm = document.getElementById("member-form");
const memberNameInput = document.getElementById("member-name");
const memberEmailInput = document.getElementById("member-email");
const memberFormStatus = document.getElementById("member-form-status");
const memberSubmitButton = document.getElementById("member-submit-button");

document.getElementById("api-root-label").textContent = API_ROOT;

let books = [];
let members = [];
let editingBookId = null;
let editingMemberId = null;

async function api(path, options) {
  const response = await fetch(`${API_ROOT}${path}`, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || body.name || `request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderBooks() {
  booksTable.innerHTML = "";
  for (const book of books) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${book.title}</td>
      <td>${book.author}</td>
      <td>${book.isbn}</td>
      <td><span class="badge ${book.available ? "available" : "unavailable"}">
        ${book.available ? "Available" : "Checked out"}
      </span></td>
      <td class="row-actions">
        <button type="button" class="icon-button" data-edit-book="${book.id}">Edit</button>
        <button type="button" class="icon-button danger" data-delete-book="${book.id}">Delete</button>
      </td>
    `;
    booksTable.appendChild(row);
  }

  for (const button of booksTable.querySelectorAll("[data-edit-book]")) {
    button.addEventListener("click", () => openBookDialog(Number(button.dataset.editBook)));
  }
  for (const button of booksTable.querySelectorAll("[data-delete-book]")) {
    button.addEventListener("click", () => deleteBook(Number(button.dataset.deleteBook)));
  }
}

function renderMembers() {
  membersTable.innerHTML = "";
  for (const member of members) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${member.name}</td>
      <td>${member.email}</td>
      <td class="row-actions">
        <button type="button" class="icon-button" data-edit-member="${member.id}">Edit</button>
        <button type="button" class="icon-button danger" data-delete-member="${member.id}">Delete</button>
      </td>
    `;
    membersTable.appendChild(row);
  }

  for (const button of membersTable.querySelectorAll("[data-edit-member]")) {
    button.addEventListener("click", () => openMemberDialog(Number(button.dataset.editMember)));
  }
  for (const button of membersTable.querySelectorAll("[data-delete-member]")) {
    button.addEventListener("click", () => deleteMember(Number(button.dataset.deleteMember)));
  }
}

function renderDeletedBooks(deletedBooks) {
  deletedBooksTable.innerHTML = deletedBooks.length
    ? ""
    : `<tr><td colspan="3" class="empty-row">No deleted books.</td></tr>`;
  for (const book of deletedBooks) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${book.title}</td>
      <td>${book.author}</td>
      <td class="row-actions">
        <button type="button" class="icon-button" data-restore-book="${book.id}">Restore</button>
      </td>
    `;
    deletedBooksTable.appendChild(row);
  }

  for (const button of deletedBooksTable.querySelectorAll("[data-restore-book]")) {
    button.addEventListener("click", () => restoreBook(Number(button.dataset.restoreBook)));
  }
}

function renderDeletedMembers(deletedMembers) {
  deletedMembersTable.innerHTML = deletedMembers.length
    ? ""
    : `<tr><td colspan="3" class="empty-row">No deleted members.</td></tr>`;
  for (const member of deletedMembers) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${member.name}</td>
      <td>${member.email}</td>
      <td class="row-actions">
        <button type="button" class="icon-button" data-restore-member="${member.id}">Restore</button>
      </td>
    `;
    deletedMembersTable.appendChild(row);
  }

  for (const button of deletedMembersTable.querySelectorAll("[data-restore-member]")) {
    button.addEventListener("click", () => restoreMember(Number(button.dataset.restoreMember)));
  }
}

function renderRentals(rentals) {
  rentalsTable.innerHTML = "";
  for (const rental of rentals) {
    const row = document.createElement("tr");
    const returned = Boolean(rental.returnedAt);
    row.innerHTML = `
      <td>${rental.bookTitle}</td>
      <td>${rental.memberName}</td>
      <td>${formatDate(rental.checkedOutAt)}</td>
      <td>${formatDate(rental.dueAt)}</td>
      <td>${formatDate(rental.returnedAt)}</td>
      <td><button class="return-button" data-id="${rental.id}" ${returned ? "disabled" : ""}>
        ${returned ? "Returned" : "Return"}
      </button></td>
    `;
    rentalsTable.appendChild(row);
  }

  for (const button of rentalsTable.querySelectorAll(".return-button:not(:disabled)")) {
    button.addEventListener("click", () => returnBook(button.dataset.id));
  }
}

function renderCheckoutOptions() {
  const availableBooks = books.filter((book) => book.available);
  checkoutBookSelect.innerHTML = availableBooks
    .map((book) => `<option value="${book.id}">${book.title} — ${book.author}</option>`)
    .join("");
  checkoutMemberSelect.innerHTML = members
    .map((member) => `<option value="${member.id}">${member.name}</option>`)
    .join("");

  const submitButton = checkoutForm.querySelector("button");
  submitButton.disabled = availableBooks.length === 0;
}

async function loadAll() {
  const [booksData, membersData, rentalsData, settings, deletedBooks, deletedMembers] = await Promise.all([
    api("/books"),
    api("/members"),
    api("/rentals"),
    api("/settings"),
    api("/books/deleted"),
    api("/members/deleted"),
  ]);
  books = booksData;
  members = membersData;

  renderBooks();
  renderMembers();
  renderRentals(rentalsData);
  renderDeletedBooks(deletedBooks);
  renderDeletedMembers(deletedMembers);
  renderCheckoutOptions();
  rentalPeriodHint.textContent = `Books are due back ${settings.rentalPeriodDays} day(s) after checkout.`;
}

async function returnBook(id) {
  try {
    await api(`/rentals/${id}/return`, { method: "POST" });
    await loadAll();
  } catch (err) {
    checkoutStatus.textContent = `Return failed: ${err.message}`;
    checkoutStatus.className = "status error";
  }
}

checkoutForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  checkoutStatus.textContent = "";
  checkoutStatus.className = "status";

  try {
    await api("/rentals", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        bookId: Number(checkoutBookSelect.value),
        memberId: Number(checkoutMemberSelect.value),
      }),
    });
    checkoutStatus.textContent = "Checked out!";
    checkoutStatus.className = "status success";
    await loadAll();
  } catch (err) {
    // The dropdowns only ever list available, non-deleted books/members,
    // so this should be rare in practice — most likely someone else just
    // checked the same book out (see checkout_book.sql's guard) between
    // this page loading and the form being submitted.
    checkoutStatus.textContent = `Checkout failed: ${err.message} (someone may have just checked this book out)`;
    checkoutStatus.className = "status error";
    await loadAll();
  }
});

// --- Books: add/edit dialog + Open Library lookup -------------------------

function openBookDialog(bookId) {
  editingBookId = bookId;
  bookForm.reset();
  bookFormStatus.textContent = "";
  bookLookupStatus.textContent = "";
  bookLookupResults.innerHTML = "";
  bookLookupQuery.value = "";

  if (bookId === null) {
    bookDialogTitle.textContent = "Add a book";
    bookSubmitButton.textContent = "Add book";
    bookLookupSection.hidden = false;
  } else {
    const book = books.find((b) => b.id === bookId);
    bookDialogTitle.textContent = "Edit book";
    bookSubmitButton.textContent = "Save changes";
    // Editing is a plain field edit, not a re-lookup — searching Open
    // Library again would suggest replacing the book, which isn't what an
    // edit is for.
    bookLookupSection.hidden = true;
    bookTitleInput.value = book.title;
    bookAuthorInput.value = book.author;
    bookIsbnInput.value = book.isbn;
  }

  bookDialog.showModal();
}

document.getElementById("add-book-button").addEventListener("click", () => openBookDialog(null));
document.getElementById("book-cancel-button").addEventListener("click", () => bookDialog.close());

bookLookupButton.addEventListener("click", async () => {
  const title = bookLookupQuery.value.trim();
  if (!title) return;

  bookLookupStatus.textContent = "Searching Open Library…";
  bookLookupResults.innerHTML = "";
  try {
    const results = await api(`/books/lookup?title=${encodeURIComponent(title)}`);
    bookLookupStatus.textContent = results.length === 0 ? "No matches found." : "";
    bookLookupResults.innerHTML = results
      .map((result, index) => {
        const author = result.author_name?.[0] ?? "unknown author";
        const year = result.first_publish_year ?? "?";
        return `<li data-index="${index}">${result.title}<small>${author} · first published ${year}</small></li>`;
      })
      .join("");

    for (const item of bookLookupResults.querySelectorAll("li")) {
      item.addEventListener("click", () => {
        const result = results[Number(item.dataset.index)];
        bookTitleInput.value = result.title;
        bookAuthorInput.value = result.author_name?.[0] ?? "";
        bookIsbnInput.value = result.isbn?.[0] ?? "";
      });
    }
  } catch (err) {
    bookLookupStatus.textContent = `Search failed: ${err.message}`;
  }
});

bookForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  bookFormStatus.textContent = "";

  const payload = {
    title: bookTitleInput.value.trim(),
    author: bookAuthorInput.value.trim(),
    isbn: bookIsbnInput.value.trim(),
  };

  try {
    if (editingBookId === null) {
      await api("/books", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    } else {
      await api(`/books/${editingBookId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    }
    bookDialog.close();
    await loadAll();
  } catch (err) {
    bookFormStatus.textContent = `Save failed: ${err.message}`;
  }
});

async function deleteBook(id) {
  if (!confirm("Delete this book? It won't be lost — you can restore it from the Deleted books list any time.")) return;
  try {
    await api(`/books/${id}`, { method: "DELETE" });
    await loadAll();
  } catch (err) {
    alert(`Couldn't delete this book: ${err.message}`);
  }
}

async function restoreBook(id) {
  try {
    await api(`/books/${id}/restore`, { method: "POST" });
    await loadAll();
  } catch (err) {
    alert(`Couldn't restore this book: ${err.message}`);
  }
}

// --- Members: add/edit dialog ----------------------------------------------

function openMemberDialog(memberId) {
  editingMemberId = memberId;
  memberForm.reset();
  memberFormStatus.textContent = "";

  if (memberId === null) {
    memberDialogTitle.textContent = "Add a member";
    memberSubmitButton.textContent = "Add member";
  } else {
    const member = members.find((m) => m.id === memberId);
    memberDialogTitle.textContent = "Edit member";
    memberSubmitButton.textContent = "Save changes";
    memberNameInput.value = member.name;
    memberEmailInput.value = member.email;
  }

  memberDialog.showModal();
}

document.getElementById("add-member-button").addEventListener("click", () => openMemberDialog(null));
document.getElementById("member-cancel-button").addEventListener("click", () => memberDialog.close());

memberForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  memberFormStatus.textContent = "";

  const payload = { name: memberNameInput.value.trim(), email: memberEmailInput.value.trim() };

  try {
    if (editingMemberId === null) {
      await api("/members", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    } else {
      await api(`/members/${editingMemberId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    }
    memberDialog.close();
    await loadAll();
  } catch (err) {
    memberFormStatus.textContent = `Save failed: ${err.message}`;
  }
});

async function deleteMember(id) {
  if (!confirm("Delete this member? They won't be lost — you can restore them from the Deleted members list any time."))
    return;
  try {
    await api(`/members/${id}`, { method: "DELETE" });
    await loadAll();
  } catch (err) {
    alert(`Couldn't delete this member: ${err.message}`);
  }
}

async function restoreMember(id) {
  try {
    await api(`/members/${id}/restore`, { method: "POST" });
    await loadAll();
  } catch (err) {
    alert(`Couldn't restore this member: ${err.message}`);
  }
}

loadAll().catch((err) => {
  checkoutStatus.textContent = `Failed to load library data: ${err.message}`;
  checkoutStatus.className = "status error";
});
