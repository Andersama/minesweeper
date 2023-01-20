// imgui_template.cpp : Defines the entry point for the application.
//

#include "imgui_template.h"

// IMGUI and glfw includes
#define IMGUI_IMPLEMENTATION
#include <gl/glew.h>
#include <GLFW/glfw3.h>
#include "imgui/imgui.h"
#include "imgui/imgui_stdlib.h"
#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
//we need this to change tesselation tolerance
#include "imgui/imgui_internal.h"
#include "zpp_bits.h"
#include "sodium/crypto_stream_xchacha20.h"
#include "sodium/randombytes.h"
#include <vector>
#include <array>
#include <chrono>
#include <span>

static void glfw_error_callback(int error, const char* description)
{
	fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

struct glfw3_setup_t {
	int err_code;
	GLFWwindow* window;
};

glfw3_setup_t glfw3_setup(uint32_t default_window_width, uint32_t default_window_height, bool fullscreen = false) {
	// Setup window
	glfwSetErrorCallback(glfw_error_callback);
	if (!glfwInit())
		return { 1,nullptr };

	//vg::Context svg_ctx;
	// Decide GL+GLSL versions
#if defined(IMGUI_IMPL_OPENGL_ES2)
	// GL ES 2.0 + GLSL 100
	const char* glsl_version = "#version 100";
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
	glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(__APPLE__)
	// GL 3.2 + GLSL 150
	const char* glsl_version = "#version 150";
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
	glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // Required on Mac
#else
	// GL 3.0 + GLSL 130
	const char* glsl_version = "#version 130";
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
	//glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
	//glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // 3.0+ only
#endif
	//GLFWmonitor* monitor = fullscreen ? glfwGetPrimaryMonitor() : NULL;
	GLFWmonitor* monitor = NULL;
	// Create window with graphics context
	GLFWwindow* window = glfwCreateWindow(default_window_width, default_window_height, "minesweeper", monitor, NULL);
	if (window == NULL)
		return { 1, nullptr };
	glfwMakeContextCurrent(window);
	glfwSwapInterval(1); // Enable vsync

	// Setup Dear ImGui context
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
	//io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls

	// Setup Dear ImGui style
	ImGui::StyleColorsDark();
	//ImGui::StyleColorsLight();

	// Setup Platform/Renderer backends
	ImGui_ImplGlfw_InitForOpenGL(window, true);
	ImGui_ImplOpenGL3_Init(glsl_version);

	return { 0, window };
}

enum class mine_flag : uint16_t {
	hidden = 0x1,
	flagged = 0x2,
	mine = 0x4,
	flood = 0x8,
};

struct mine {
	uint16_t nearby = {};
	uint16_t flags = {};
};

constexpr bool is_mine(mine& m) noexcept {
	return m.flags & (uint16_t)mine_flag::mine;
}

constexpr bool is_flagged(mine& m) noexcept {
	return m.flags & (uint16_t)mine_flag::flagged;
}

constexpr bool is_hidden(mine& m) noexcept {
	return m.flags & (uint16_t)mine_flag::hidden;
}

constexpr bool is_near_mine(mine& m) noexcept {
	return m.nearby > 0;
}

constexpr bool is_flooded(mine& m) noexcept {
	return m.flags & (uint16_t)mine_flag::flood;
}

uint32_t xchacha_random(const unsigned char* number_only_used_once, const unsigned char* key, uint32_t range) {
	uint32_t limit = (~uint32_t{ 0 } - (range - 1));
	uint32_t limit_d = limit / range;
	uint32_t limit_r = limit % range;

	uint32_t sample;
	uint64_t m;
	uint32_t h_value;
	uint32_t l_value;

	std::array<uint32_t, (crypto_stream_xchacha20_NONCEBYTES / 4) + 1>* n = (std::array<uint32_t, (crypto_stream_xchacha20_NONCEBYTES / 4) + 1>*)number_only_used_once;
	std::array<uint32_t, (crypto_stream_xchacha20_KEYBYTES / 4) + 1>* k = (std::array<uint32_t, (crypto_stream_xchacha20_KEYBYTES / 4) + 1>*)
		key;

	do {
		crypto_stream_xchacha20((unsigned char*)&sample, sizeof(sample), number_only_used_once, key);
		n->operator[](0) += 1;

		m = uint64_t{ sample } *uint64_t{ range };
		h_value = m >> 32;     // high part of m
		l_value = uint32_t(m); // low part of m
	} while (l_value < limit_r); // discard out of bounds 

	return h_value;
}

void minesweeper_start(std::vector<mine>& tiles, uint32_t x_tiles, uint32_t y_tiles, uint64_t mine_count) {
	uint64_t total_tiles = (x_tiles * y_tiles);

	tiles.clear();
	tiles.reserve(total_tiles); //largest size

	if (total_tiles <= 0)
		return;

	for (size_t i = 0; i < total_tiles; i++) {
		tiles.emplace_back();
	}

	uint64_t timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
	std::array<uint32_t, (crypto_stream_xchacha20_NONCEBYTES / 4) + 1> nonce = {};
	std::memcpy(nonce.data(), &timestamp, std::min(sizeof(timestamp), sizeof(nonce)));

	std::array<uint32_t, (crypto_stream_xchacha20_KEYBYTES / 4) + 1> key = {};
	randombytes_buf(key.data(), sizeof(key));

	for (size_t i = 0; i < total_tiles; i++) {
		tiles[i].flags = (uint16_t)mine_flag::hidden | ((uint16_t)mine_flag::mine * (i < mine_count));
	}

	if (mine_count >= total_tiles)
		return;

	// random permutation
	for (size_t i = 0; i < total_tiles; i++) {
		uint32_t limit = (~uint32_t{ 0 } - ((total_tiles - i) - 1));
		uint32_t limit_d = limit / (total_tiles - i);
		uint32_t limit_r = limit % (total_tiles - i);

		uint32_t sample;
		uint64_t m;
		uint32_t h_value;
		uint32_t l_value;
		do {
			crypto_stream_xchacha20((unsigned char*)&sample, sizeof(sample), (const unsigned char*)nonce.data(), (const unsigned char*)key.data());
			nonce[0] += 1;

			m = uint64_t{ sample } *uint64_t{ total_tiles };
			h_value = m >> 32;     // high part of m
			l_value = uint32_t(m); // low part of m
		} while (l_value < limit_r); // discard out of bounds 

		std::swap(tiles[i], tiles[h_value]);
	}
}

void minesweeper_swap_to_empty_tile(std::vector<mine>& tiles, std::vector<uint32_t>& idxs, uint32_t tile) {
	idxs.clear();
	if (tile >= tiles.size())
		return;

	if (!is_mine(tiles[tile]))
		return;

	idxs.reserve(tiles.capacity());
	for (size_t i = 0; i < tiles.size(); i++) {
		if (!is_mine(tiles[i]))
			idxs.emplace_back(i);
	}

	uint64_t timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
	std::array<uint32_t, (crypto_stream_xchacha20_NONCEBYTES / 4) + 1> nonce = {};
	std::memcpy(nonce.data(), &timestamp, std::min(sizeof(timestamp), sizeof(nonce)));

	std::array<uint32_t, (crypto_stream_xchacha20_KEYBYTES / 4) + 1> key = {};
	randombytes_buf(key.data(), sizeof(key));

	uint32_t limit = (~uint32_t{ 0 } - (idxs.size() - 1));
	uint32_t limit_d = limit / idxs.size();
	uint32_t limit_r = limit % idxs.size();

	uint32_t sample;
	uint64_t m;
	uint32_t h_value;
	uint32_t l_value;

	do {
		crypto_stream_xchacha20((unsigned char*)&sample, sizeof(sample), (const unsigned char*)nonce.data(), (const unsigned char*)key.data());
		nonce[0] += 1;

		m = uint64_t{ sample } *uint64_t{ idxs.size() };
		h_value = m >> 32;     // high part of m
		l_value = uint32_t(m); // low part of m
	} while (l_value < limit_r); // discard out of bounds 

	std::swap(tiles[tile], tiles[h_value]);
}

void minesweeper_neighbors_2d(std::vector<mine>& tiles, uint32_t x_tiles, uint32_t y_tiles) {
	struct offset {
		int x = {};
		int y = {};
	};

	std::array<offset, 8> offsets = {
		offset{-1, -1}, offset{0, -1}, offset{1, -1},
		offset{-1,  0},                offset{1,  0},
		offset{-1,  1}, offset{0,  1}, offset{1,  1}
	};

	for (size_t i = 0; i < tiles.size(); i++) {
		tiles[i].nearby = 0;
		offset position = { i % x_tiles, i / x_tiles };
		for (size_t o = 0; o < offsets.size(); o++) {
			offset test_position = { position.x + offsets[o].x, position.y + offsets[o].y };
			uint32_t test_idx = test_position.y * x_tiles + test_position.x;

			bool within_grid = (test_position.x >= 0 && test_position.x < x_tiles)
				&& (test_position.y >= 0 && test_position.y < y_tiles);
			tiles[i].nearby += within_grid && is_mine(tiles[test_idx]);
		}
	}
}

// scanline flood fill
void minesweeper_reveal(std::vector<mine>& tiles, std::vector<uint32_t>& idxs, uint32_t x_tiles, uint32_t y_tiles, uint32_t tile) {
	idxs.clear();

	for (size_t i = 0; i < tiles.size(); i++) {
		tiles[i].flags |= (uint16_t)mine_flag::flood;
	}

	idxs.emplace_back(tile);

	tiles[tile].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
	if (is_near_mine(tiles[tile])) {
		return;
	}

	for (size_t i = 0; i < idxs.size(); i++) {
		tile = idxs[i];

		tiles[tile].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);

		bool wall_above = true;
		bool wall_below = true;

		{
			size_t idx_above = tile - x_tiles;
			if (idx_above < tiles.size()) {
				bool above_near = is_near_mine(tiles[idx_above]);
				if (wall_above == true && !above_near && is_flooded(tiles[idx_above])) {
					idxs.emplace_back(idx_above);
					wall_above = false;
				}
				else if (above_near) {
					wall_above = true;
				}
				tiles[idx_above].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			}

			size_t idx_below = tile + x_tiles;
			if (idx_below < tiles.size()) {
				bool below_near = is_near_mine(tiles[idx_below]);
				if (wall_below == true && !below_near && is_flooded(tiles[idx_below])) {
					idxs.emplace_back(idx_below);
					wall_below = false;
				}
				else if (below_near) {
					wall_below = true;
				}
				tiles[idx_below].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			}
		}

		if (is_near_mine(tiles[tile])) { //is_hidden(tiles[idx])
			continue;
		}

		uint32_t tile_y = tile / x_tiles;
		for (size_t idx = tile + 1; idx < tiles.size(); idx++) {
			{
				uint32_t idx_y = idx / x_tiles;
				if (idx_y != tile_y)
					break;
			}

			size_t idx_above = idx - x_tiles;
			if (idx_above < tiles.size()) {
				bool above_near = is_near_mine(tiles[idx_above]);
				if (wall_above == true && !above_near && is_flooded(tiles[idx_above])) {
					idxs.emplace_back(idx_above);
					wall_above = false;
				}
				else if (above_near) {

					wall_above = true;
				}
				tiles[idx_above].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			}

			size_t idx_below = idx + x_tiles;
			if (idx_below < tiles.size()) {
				bool below_near = is_near_mine(tiles[idx_below]);
				if (wall_below == true && !below_near && is_flooded(tiles[idx_below])) {
					idxs.emplace_back(idx_below);
					wall_below = false;
				}
				else if (below_near) {

					wall_below = true;
				}
				tiles[idx_below].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			}

			tiles[idx].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			if (is_near_mine(tiles[idx])) { //is_hidden(tiles[idx])
				break;
			}
		}

		wall_above = true;
		wall_below = true;
		for (size_t idx = tile - 1; idx < tiles.size(); idx--) {
			{
				uint32_t idx_y = idx / x_tiles;
				if (idx_y != tile_y)
					break;
			}

			size_t idx_above = idx - x_tiles;
			if (idx_above < tiles.size()) {
				bool above_near = is_near_mine(tiles[idx_above]);
				if (wall_above == true && !above_near && is_flooded(tiles[idx_above])) {
					idxs.emplace_back(idx_above);
					wall_above = false;
				}
				else if (above_near) {

					wall_above = true;
				}
				tiles[idx_above].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			}

			size_t idx_below = idx + x_tiles;
			if (idx_below < tiles.size()) {
				bool below_near = is_near_mine(tiles[idx_below]);
				if (wall_below == true && !below_near && is_flooded(tiles[idx_below])) {
					idxs.emplace_back(idx_below);
					wall_below = false;
				}
				else if (below_near) {

					wall_below = true;
				}
				tiles[idx_below].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			}

			tiles[idx].flags &= ~((uint16_t)mine_flag::flood | (uint16_t)mine_flag::hidden);
			if (is_near_mine(tiles[idx])) { //is_hidden(tiles[idx])
				break;
			}
		}
	}

}

size_t minesweeper_minimum_clicks(std::vector<mine>& copy, const std::vector<mine>& tiles, std::vector<uint32_t>& idxs, uint32_t x_tiles, uint32_t y_tiles) {
	copy.clear();
	copy.assign(tiles.data(), tiles.data() + tiles.size());

	for (size_t i = 0; i < copy.size(); i++) {
		copy[i].flags |= (uint16_t)mine_flag::hidden;
	}
	size_t count = 0;
	
	size_t shown = 0;
	size_t mines_revealed = 0;
	// search for a thing to click and click it, do big impact ones first
	for (size_t i = 0; i < copy.size(); i++) {
		if (!is_mine(copy[i]) && is_hidden(copy[i]) && !is_near_mine(copy[i])) {
			minesweeper_reveal(copy, idxs, x_tiles, y_tiles, i);
			count++;
		}
	}
	// click on individiual hints
	for (size_t i = 0; i < copy.size(); i++) {
		if (!is_mine(copy[i]) && is_hidden(copy[i])) {
			minesweeper_reveal(copy, idxs, x_tiles, y_tiles, i);
			count++;
		}
	}
	return count;
}

size_t minesweeper_start_with_minimum_clicks(std::vector<mine>& copy, std::vector<mine>& tiles, std::vector<uint32_t>& idxs, uint32_t x_tiles, uint32_t y_tiles, uint64_t mine_count, size_t minimum_clicks = 3) {
	size_t clicks = 0;
	std::vector<mine> best_board;
	uint32_t max_clicks = 0;
	uint32_t max_tries = 100;
	do {
		minesweeper_start(tiles, x_tiles, y_tiles, mine_count);
		clicks = minesweeper_minimum_clicks(copy, tiles, idxs, x_tiles, y_tiles);
		max_tries++;
		if (clicks > max_clicks) {
			best_board.assign(tiles.data(), tiles.data() + tiles.size());
			max_clicks = clicks;
		}
	} while (clicks < minimum_clicks && max_tries < 100);

	// keep the "most difficult" board generated
	tiles.assign(best_board.data(), best_board.data() + best_board.size());
	return max_clicks;
}

int main(int argc, char** argv)
{
	uint32_t window_width = 1920;
	uint32_t window_height = 1080;
	glfw3_setup_t r = glfw3_setup(window_width, window_height);

	bool show_demo_window = true;

	std::vector<mine> tiles_copy;
	std::vector<mine> tiles;
	std::vector<uint32_t> idxs;

	uint64_t wins = { 0 };
	uint64_t tries = { 0 };
	uint64_t losses = { 0 };

	uint32_t x_tiles = 9;
	uint32_t y_tiles = 9;
	uint32_t mines = 10;

	uint32_t total_tiles = (x_tiles * y_tiles);

	constexpr uint32_t x_tiles_max = 100;
	constexpr uint32_t y_tiles_max = 100;

	tiles.reserve(x_tiles_max * y_tiles_max); //largest size
	idxs.reserve(x_tiles_max * y_tiles_max);

	//minesweeper_start(tiles, x_tiles, y_tiles, mines);
	size_t clicks_required = minesweeper_start_with_minimum_clicks(tiles_copy, tiles, idxs, x_tiles, y_tiles, mines, 3);

	bool first_click = true;
	//minesweeper_start(tiles, )

	ImU32 gray = ImU32{ 0xffc1c0c1 };
	ImU32 dark_gray = ImU32{ 0xff4d4d4d };
	ImU32 red = ImU32{ 0xff2828f2 };
	ImU32 black = ImU32{ 0xff030303 };

	ImU32 hover_gray = ImU32{ 0xffc9c8c9 };
	ImU32 hover_dark_gray = ImU32{ 0xff4d4d4d };
	ImU32 hover_red = ImU32{ 0xff2828f2 };
	ImU32 hover_black = ImU32{ 0xff090909 };

	bool has_won = false;
	bool has_lost = false;

	uint64_t timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

	while (!glfwWindowShouldClose(r.window))
	{
		// Poll and handle events (inputs, window resize, etc.)
		// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
		// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
		// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
		// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
		glfwPollEvents();
		// glfwWaitEvents();

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		//ImGui::ShowDemoWindow(&show_demo_window);

		int width;
		int height;
		glfwGetFramebufferSize(r.window, &width, &height);
		ImGui::SetNextWindowSize(ImVec2(width, height)); // ensures ImGui fits the GLFW window

		int tile_xdim = width / x_tiles;
		int tile_ydim = height / y_tiles;

		int tile_dim = std::min(tile_xdim, tile_ydim);

		ImGui::SetNextWindowPos(ImVec2(0, 0));
		{
			ImGui::Begin("minesweeper", nullptr, ImGuiWindowFlags_::ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_::ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_::ImGuiWindowFlags_NoCollapse
			);

			float line_width = tile_dim / 20.0f;

			ImVec2 mouse = ImGui::GetMousePos();

			bool ok_mouse = ImGui::IsMousePosValid(&mouse);

			ImVec2 grid_top_left = { (float)0 * tile_dim, (float)0 * tile_dim };
			ImVec2 grid_btm_right = { (float)(x_tiles + 1) * tile_dim, (float)(y_tiles + 1) * tile_dim };
			bool mouse_in_grid = ImGui::IsMouseHoveringRect(grid_top_left, grid_btm_right);

			bool left_clicked = ok_mouse && mouse_in_grid && ImGui::IsMouseClicked(ImGuiMouseButton_::ImGuiMouseButton_Left);

			bool right_clicked = ok_mouse && mouse_in_grid && ImGui::IsMouseClicked(ImGuiMouseButton_::ImGuiMouseButton_Right);

			ImDrawList* draw_list = ImGui::GetWindowDrawList();
			for (size_t i = 0; i < tiles.size(); i++) {
				uint32_t grid_y = i / x_tiles;
				uint32_t grid_x = i % x_tiles;
				//rgba -> abgr

				ImVec2 top_left = { (float)grid_x * tile_dim, (float)grid_y * tile_dim };
				ImVec2 btm_right = { (float)(grid_x + 1) * tile_dim, (float)(grid_y + 1) * tile_dim };

				bool hovering_over_tile = ImGui::IsMouseHoveringRect(top_left, btm_right);

				uint16_t& flags = tiles[i].flags;
				if (right_clicked && hovering_over_tile && (flags & (uint16_t)mine_flag::hidden)) {
					flags ^= (uint16_t)mine_flag::flagged;
				}
				/*
				if (left_clicked && hovering_over_tile && !((flags & (uint16_t)mine_flag::hidden) && (flags & (uint16_t)mine_flag::flagged))) {
					flags &= ~((uint16_t)mine_flag::hidden);
				}
				*/
				if (first_click && left_clicked && hovering_over_tile) { //!((flags & (uint16_t)mine_flag::hidden) && (flags & (uint16_t)mine_flag::flagged))
					first_click = false;

					minesweeper_swap_to_empty_tile(tiles, idxs, i);
					minesweeper_neighbors_2d(tiles, x_tiles, y_tiles);
				}

				if (left_clicked && hovering_over_tile && is_hidden(tiles[i]) && !is_flagged(tiles[i])) {
					minesweeper_reveal(tiles, idxs, x_tiles, y_tiles, i);
				}

				if (ImGui::IsMouseHoveringRect(top_left, btm_right)) {
					ImU32 color = (flags & (uint16_t)mine_flag::hidden) ? hover_gray : hover_dark_gray;
					color = ((flags & (uint16_t)mine_flag::flagged) && (flags & (uint16_t)mine_flag::hidden)) ? hover_red : color;
					color = (flags & (uint16_t)mine_flag::mine && !(flags & (uint16_t)mine_flag::hidden)) ? hover_black : color;

					draw_list->AddRectFilled(top_left, btm_right, color);

				}
				else {
					ImU32 color = (flags & (uint16_t)mine_flag::hidden) ? gray : dark_gray;
					color = ((flags & (uint16_t)mine_flag::flagged) && (flags & (uint16_t)mine_flag::hidden)) ? red : color;
					color = (flags & (uint16_t)mine_flag::mine && !(flags & (uint16_t)mine_flag::hidden)) ? black : color;

					draw_list->AddRectFilled(top_left, btm_right, color);
				}

				char txt[2] = { tiles[i].nearby + '0', 0 };
				if (!(flags & (uint16_t)mine_flag::hidden) && tiles[i].nearby) {
					draw_list->AddText(ImVec2{ (top_left.x + btm_right.x) / 2.0f, (top_left.y + btm_right.y) / 2.0f }, ImU32{ 0xffffffff }, (const char*)&txt[0], (const char*)&txt[1]);
				}
			}

			size_t shown = 0;
			size_t mines_revealed = 0;
			for (size_t i = 0; i < tiles.size(); i++) {
				shown += !is_hidden(tiles[i]) && !is_mine(tiles[i]);
				mines_revealed += !is_hidden(tiles[i]) && is_mine(tiles[i]);
			}

			has_lost = mines_revealed > 0;
			has_won = !has_lost && ((tiles.size() - shown) == mines);
			
			if (has_won || has_lost) {
				const char* text = has_won ? "You Won!" : "You Lost!";
				ImGui::OpenPopup(text);
				if (ImGui::BeginPopupModal(text)) {
					if (ImGui::Button("Easy")) {
						losses += has_lost;
						wins += has_won;
						tries++;

						first_click = true;
						x_tiles = 9;
						y_tiles = 9;
						mines = 10;
						//minesweeper_start(tiles, x_tiles, y_tiles, mines);
						clicks_required = minesweeper_start_with_minimum_clicks(tiles_copy, tiles, idxs, x_tiles, y_tiles, mines, 3);
					}
					else if (ImGui::Button("Intermediate")) {
						losses += has_lost;
						wins += has_won;
						tries++;

						first_click = true;
						x_tiles = 16;
						y_tiles = 16;
						mines = 40;
						//minesweeper_start(tiles, x_tiles, y_tiles, mines);
						clicks_required = minesweeper_start_with_minimum_clicks(tiles_copy, tiles, idxs, x_tiles, y_tiles, mines, 6);
					}
					else if (ImGui::Button("Expert")) {
						losses += has_lost;
						wins += has_won;
						tries++;

						first_click = true;
						x_tiles = 30;
						y_tiles = 16;
						mines = 99;
						//minesweeper_start(tiles, x_tiles, y_tiles, mines);
						clicks_required = minesweeper_start_with_minimum_clicks(tiles_copy, tiles, idxs, x_tiles, y_tiles, mines, 9);
					}
					ImGui::EndPopup();
				}
			}

			// draw lines
			for (size_t i = 0; i < (x_tiles + 1); i++) {
				draw_list->AddLine(ImVec2{ (float)i * tile_dim, (float)0.0f },
					ImVec2{ (float)i * tile_dim, (float)y_tiles * tile_dim }, dark_gray, line_width);
			}

			for (size_t i = 0; i < (y_tiles + 1); i++) {
				draw_list->AddLine(ImVec2{ (float)0.0f, (float)i * tile_dim },
					ImVec2{ (float)x_tiles * tile_dim, (float)i * tile_dim }, dark_gray, line_width);
			}

			ImGui::End();
		}

		ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
		// Rendering
		ImGui::Render();
		int display_w, display_h;
		glfwGetFramebufferSize(r.window, &display_w, &display_h);
		glViewport(0, 0, display_w, display_h);
		glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

		glfwSwapBuffers(r.window);
	}

	// Cleanup
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwDestroyWindow(r.window);
	glfwTerminate();

	return r.err_code;
}

// boilerplate ~for windows build~
int WinMain(int argc, char** argv) {
	return main(argc, argv);
}