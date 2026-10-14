"use strict";

const productGrid = document.querySelector("#product-grid");

function createProductCard(product) {
  const card = document.createElement("article");
  card.className = "product-card";

  const image = document.createElement("img");
  image.src = product.image;
  image.alt = product.image_alt;
  image.loading = "lazy";
  card.append(image);

  const category = document.createElement("span");
  category.className = "product-tag";
  category.textContent = product.category;
  card.append(category);

  const title = document.createElement("h3");
  title.textContent = product.name;
  card.append(title);

  const description = document.createElement("p");
  description.textContent = product.description;
  card.append(description);

  const price = document.createElement("span");
  price.className = "price";
  price.textContent = new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: product.currency.toUpperCase(),
  }).format(product.price_cents / 100);
  card.append(price);

  const buyForm = document.createElement("form");
  buyForm.className = "product-buy";
  buyForm.method = "post";
  buyForm.action = "/create-checkout-session";

  const productId = document.createElement("input");
  productId.type = "hidden";
  productId.name = "product_id";
  productId.value = product.id;
  buyForm.append(productId);

  const buyButton = document.createElement("button");
  buyButton.className = "btn btn-primary";
  buyButton.type = "submit";
  buyButton.textContent = "Buy";
  buyForm.append(buyButton);
  card.append(buyForm);

  return card;
}

async function loadProducts() {
  if (!productGrid) {
    return;
  }

  try {
    const response = await fetch("/api/products");
    if (!response.ok) {
      throw new Error(`Product request failed with status ${response.status}`);
    }

    const products = await response.json();
    productGrid.replaceChildren(...products.map(createProductCard));
  } catch (error) {
    console.error("Unable to load FITTRACK products.", error);
    const message = document.createElement("p");
    message.className = "product-status";
    message.textContent = "Products could not be loaded. Please refresh the page or try again later.";
    productGrid.replaceChildren(message);
  }
}

loadProducts();
